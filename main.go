package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const appVersion = "2.1.0"
const readBufferSize = 64 * 1024

type options struct {
	url             string
	ipFiles         string
	ipText          string
	port            int
	workers         int
	pingCount       int
	downCount       int
	downloadTime    time.Duration
	requestTimeout  time.Duration
	probeTimeout    time.Duration
	samplesPerCIDR  int
	allIP           bool
	maxExpand       uint64
	outDir          string
	coloFilter      string
	streamWindowMiB uint64
	connWindowMiB   uint64
	// testRootCAs is only used by package tests; nil keeps normal system-root verification.
	testRootCAs *x509.CertPool
}

type transfer struct {
	Protocol      string
	Bytes         int64
	Elapsed       time.Duration
	TTFB          time.Duration
	SpeedMiB      float64
	Status        int
	HTTPProto     string
	ALPN          string
	Colo          string
	ClientIP      string
	City          string
	Country       string
	ASN           string
	CFRay         string
	Location      string
	ContentLength int64
	Requests      int
	Err           string
}

type result struct {
	IP           net.IP
	TCPReceived  int
	TCPTotal     int
	TCPAvg       time.Duration
	QUICReceived int
	QUICTotal    int
	QUICAvg      time.Duration
	H1           transfer
	H2           transfer
	H3           transfer
}

func main() {
	var o options
	flag.StringVar(&o.url, "url", "https://h3.speed.cloudflare.com/__down?bytes=10000000000", "下载测速 URL（默认 Cloudflare HTTP/3 专用 10 GB 下载端点；支持自建 HTTPS 大文件端点）")
	flag.StringVar(&o.ipFiles, "f", "ip.txt,ipv6.txt", "IP/CIDR 文件，多个文件用逗号分隔")
	flag.StringVar(&o.ipText, "ip", "", "直接指定 IP/CIDR，逗号分隔；指定后仍可与 -f 合并")
	flag.IntVar(&o.port, "tp", 443, "目标 TCP/UDP 端口")
	flag.IntVar(&o.workers, "n", 160, "并发延迟探测线程数")
	flag.IntVar(&o.pingCount, "t", 4, "每个 IP 的 TCP/QUIC 握手探测次数")
	flag.IntVar(&o.downCount, "dn", 20, "按延迟排序后进行三协议下载测速的 IP 数量")
	flag.DurationVar(&o.downloadTime, "dt", 10*time.Second, "每个协议的正文测速时间，例如 15s")
	flag.DurationVar(&o.requestTimeout, "request-timeout", 6*time.Second, "下载阶段建连及等待响应头的独立超时")
	flag.DurationVar(&o.probeTimeout, "probe-timeout", 1500*time.Millisecond, "TCP connect / QUIC 握手探测超时")
	flag.IntVar(&o.samplesPerCIDR, "samples-per-cidr", 32, "每个 CIDR 随机抽样的 IP 数（对小网段最多取全部）")
	flag.BoolVar(&o.allIP, "allip", false, "展开 CIDR 内所有 IP（受 -max-expand 上限保护）")
	flag.Uint64Var(&o.maxExpand, "max-expand", 65536, "-allip 时每个 CIDR 允许展开的最大地址数")
	flag.StringVar(&o.outDir, "out", "result-dualbench", "CSV 输出目录")
	flag.StringVar(&o.coloFilter, "cfcolo", "", "仅输出指定 Cloudflare Colo；各协议排名按各自响应 Colo 过滤，例如 LAX")
	flag.Uint64Var(&o.streamWindowMiB, "quic-stream-window", 32, "QUIC 最大 Stream 接收窗口 MiB（自动扩窗上限）")
	flag.Uint64Var(&o.connWindowMiB, "quic-conn-window", 64, "QUIC 最大 Connection 接收窗口 MiB（自动扩窗上限）")
	flag.Usage = func() {
		fmt.Printf("CFST DualBench %s\n", appVersion)
		fmt.Println("对同一份 IP 候选集分别测试 TCP/HTTP1.1、TCP/HTTP2、QUIC/HTTP3；严格校验实际协议，禁止回退成绩混入排名。")
		flag.PrintDefaults()
	}
	flag.Parse()
	fileFlagExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "f" {
			fileFlagExplicit = true
		}
	})
	// A direct -ip list replaces the default range files unless -f was explicitly supplied.
	if strings.TrimSpace(o.ipText) != "" && !fileFlagExplicit {
		o.ipFiles = ""
	}

	if err := validateOptions(o); err != nil {
		fatalf("参数错误：%v", err)
	}

	parsedURL, err := url.Parse(o.url)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Hostname() == "" {
		fatalf("-url 必须是包含主机名的 HTTPS URL：%q", o.url)
	}

	ips, err := loadCandidates(o)
	if err != nil {
		fatalf("读取 IP 候选集失败：%v", err)
	}
	if len(ips) == 0 {
		fatalf("没有可测 IP。请检查 -f / -ip 输入文件或 CIDR。")
	}

	fmt.Printf("CFST DualBench %s | 候选 IP：%d | URL：%s | Port：%d\n", appVersion, len(ips), o.url, o.port)
	fmt.Printf("协议：TCP/HTTP1.1 + TCP/HTTP2 + QUIC/HTTP3（严格协议校验） | 正文测速：%s/协议\n", o.downloadTime)
	fmt.Printf("QUIC 最大接收窗口：Stream=%d MiB / Connection=%d MiB\n\n", o.streamWindowMiB, o.connWindowMiB)

	results := probeAll(ips, o, parsedURL.Hostname())
	usable := make([]result, 0, len(results))
	for _, r := range results {
		if r.TCPReceived > 0 || r.QUICReceived > 0 {
			usable = append(usable, r)
		}
	}
	if len(usable) == 0 {
		fatalf("所有 IP 的 TCP 与 QUIC 探测均失败。检查路由、防火墙、UDP/443 和 SNI/测速 URL。")
	}
	sort.Slice(usable, func(i, j int) bool { return scoreLatency(usable[i]) < scoreLatency(usable[j]) })
	if len(usable) > o.downCount {
		usable = usable[:o.downCount]
	}

	fmt.Printf("\n开始三协议下载测速：%d 个 IP；每个 IP 顺序执行三组测试，避免并发互相抢带宽。\n", len(usable))
	for i := range usable {
		fmt.Printf("[%d/%d] %s\n", i+1, len(usable), usable[i].IP)
		order := protocolOrder(i)
		for _, p := range order {
			tr := measureProtocol(usable[i].IP, p, o, parsedURL.Hostname())
			switch p {
			case "http1":
				usable[i].H1 = tr
			case "http2":
				usable[i].H2 = tr
			case "http3":
				usable[i].H3 = tr
			}
			if tr.Err != "" {
				fmt.Printf("    %-6s 失败：%s | HTTP=%d Proto=%s Colo=%s\n", strings.ToUpper(p), tr.Err, tr.Status, tr.HTTPProto, coloOrDash(tr.Colo))
			} else {
				fmt.Printf("    %-6s %8.3f MiB/s | TTFB %7.1f ms | %s | %s\n", strings.ToUpper(p), tr.SpeedMiB, float64(tr.TTFB)/float64(time.Millisecond), tr.HTTPProto, coloOrDash(tr.Colo))
			}
		}
	}

	if err := writeOutputs(usable, o); err != nil {
		fatalf("写入 CSV 失败：%v", err)
	}
	fmt.Printf("\n完成。结果目录：%s\n", o.outDir)
	fmt.Println("  result-tcp.csv      TCP connect + HTTP/1.1 下载排名")
	fmt.Println("  result-h2.csv       TCP connect + HTTP/2 下载排名")
	fmt.Println("  result-h3.csv       QUIC handshake + HTTP/3 下载排名")
	fmt.Println("  result-compare.csv  同 IP 三协议横向对照（按 HTTP/3 速度排序）")
	fmt.Println("  result-diagnostics.csv  握手、HTTP 状态、TTFB、下载错误诊断")
}

func validateOptions(o options) error {
	if o.port < 1 || o.port > 65535 {
		return fmt.Errorf("-tp 必须在 1..65535")
	}
	if o.workers < 1 || o.workers > 2000 {
		return fmt.Errorf("-n 必须在 1..2000")
	}
	if o.pingCount < 1 || o.pingCount > 20 {
		return fmt.Errorf("-t 必须在 1..20")
	}
	if o.downCount < 1 {
		return fmt.Errorf("-dn 必须大于 0")
	}
	if o.downloadTime < time.Second {
		return fmt.Errorf("-dt 不应小于 1s")
	}
	if o.requestTimeout < time.Second {
		return fmt.Errorf("-request-timeout 不应小于 1s")
	}
	if o.probeTimeout < 200*time.Millisecond || o.probeTimeout > 10*time.Second {
		return fmt.Errorf("-probe-timeout 必须在 200ms..10s")
	}
	if o.samplesPerCIDR < 1 || o.samplesPerCIDR > 100000 {
		return fmt.Errorf("-samples-per-cidr 必须在 1..100000")
	}
	if o.maxExpand < 1 {
		return fmt.Errorf("-max-expand 必须大于 0")
	}
	if o.streamWindowMiB < 1 || o.connWindowMiB < 1 {
		return fmt.Errorf("QUIC 窗口必须大于 0 MiB")
	}
	if o.streamWindowMiB > 1024 || o.connWindowMiB > 2048 {
		return fmt.Errorf("QUIC 窗口设置过大（Stream <= 1024 MiB，Connection <= 2048 MiB）")
	}
	if o.connWindowMiB < o.streamWindowMiB {
		return fmt.Errorf("QUIC Connection 窗口不应小于 Stream 窗口")
	}
	return nil
}

func loadCandidates(o options) ([]net.IP, error) {
	seen := map[string]bool{}
	out := make([]net.IP, 0, 2048)
	add := func(ip net.IP) {
		if ip == nil {
			return
		}
		ip = append(net.IP(nil), ip...)
		key := ip.String()
		if !seen[key] {
			seen[key] = true
			out = append(out, ip)
		}
	}
	if strings.TrimSpace(o.ipText) != "" {
		for _, token := range strings.Split(o.ipText, ",") {
			if err := addToken(strings.TrimSpace(token), o, add); err != nil {
				return nil, err
			}
		}
	}
	for _, file := range strings.Split(o.ipFiles, ",") {
		file = strings.TrimSpace(file)
		if file == "" {
			continue
		}
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("打开 %s：%w", file, err)
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			for _, token := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ';' || r == '\t' || r == ' ' }) {
				if err := addToken(strings.TrimSpace(token), o, add); err != nil {
					f.Close()
					return nil, fmt.Errorf("%s 第 %d 行：%w", file, lineNo, err)
				}
			}
		}
		scanErr := scanner.Err()
		closeErr := f.Close()
		if scanErr != nil {
			return nil, scanErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

func addToken(token string, o options, add func(net.IP)) error {
	if token == "" {
		return nil
	}
	if ip := net.ParseIP(token); ip != nil {
		add(normalizeIP(ip))
		return nil
	}
	ip, network, err := net.ParseCIDR(token)
	if err != nil {
		return fmt.Errorf("无效 IP/CIDR %q", token)
	}
	_ = ip
	bits, totalBits := network.Mask.Size()
	hostBits := totalBits - bits
	if hostBits < 0 {
		return fmt.Errorf("无效网络前缀 %q", token)
	}
	if o.allIP {
		if hostBits >= 63 {
			return fmt.Errorf("%s 地址数量过大，不能 -allip 展开", token)
		}
		count := uint64(1) << uint(hostBits)
		if count > o.maxExpand {
			return fmt.Errorf("%s 有 %d 个地址，超过 -max-expand=%d；请关闭 -allip 抽样", token, count, o.maxExpand)
		}
		for n := uint64(0); n < count; n++ {
			add(ipAt(network, n))
		}
		return nil
	}
	count := uint64(o.samplesPerCIDR)
	if hostBits < 63 {
		space := uint64(1) << uint(hostBits)
		if count > space {
			count = space
		}
	}
	// Small ranges are enumerated to avoid duplicate random samples.
	if hostBits <= 16 && uint64(1)<<uint(hostBits) <= count {
		for n := uint64(0); n < uint64(1)<<uint(hostBits); n++ {
			add(ipAt(network, n))
		}
		return nil
	}
	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(len(token))))
	added := 0
	attempts := 0
	local := map[string]bool{}
	for added < int(count) && attempts < int(count)*20 {
		attempts++
		offset := make([]byte, len(network.IP))
		_, _ = rng.Read(offset)
		candidate := append(net.IP(nil), network.IP...)
		for bit := bits; bit < totalBits; bit++ {
			byteIdx := bit / 8
			mask := byte(1 << uint(7-bit%8))
			if offset[byteIdx]&mask != 0 {
				candidate[byteIdx] |= mask
			} else {
				candidate[byteIdx] &^= mask
			}
		}
		key := candidate.String()
		if !local[key] {
			local[key] = true
			add(candidate)
			added++
		}
	}
	return nil
}

func normalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return append(net.IP(nil), v4...)
	}
	return append(net.IP(nil), ip.To16()...)
}
func ipAt(network *net.IPNet, offset uint64) net.IP {
	ip := append(net.IP(nil), network.IP...)
	for i := len(ip) - 1; i >= 0 && offset > 0; i-- {
		ip[i] |= byte(offset)
		offset >>= 8
	}
	return normalizeIP(ip)
}

func probeAll(ips []net.IP, o options, serverName string) []result {
	jobs := make(chan net.IP)
	out := make(chan result, len(ips))
	var wg sync.WaitGroup
	workers := o.workers
	if workers > len(ips) {
		workers = len(ips)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				r := result{IP: ip, TCPTotal: o.pingCount, QUICTotal: o.pingCount}
				r.TCPReceived, r.TCPAvg = tcpPing(ip, o)
				r.QUICReceived, r.QUICAvg = quicPing(ip, o, serverName)
				out <- r
			}
		}()
	}
	go func() {
		for _, ip := range ips {
			jobs <- ip
		}
		close(jobs)
		wg.Wait()
		close(out)
	}()
	results := make([]result, 0, len(ips))
	for r := range out {
		results = append(results, r)
		if len(results)%100 == 0 || len(results) == len(ips) {
			fmt.Printf("\r延迟探测：%d/%d", len(results), len(ips))
		}
	}
	fmt.Println()
	return results
}

func tcpPing(ip net.IP, o options) (int, time.Duration) {
	var ok int
	var total time.Duration
	address := net.JoinHostPort(ip.String(), strconv.Itoa(o.port))
	for i := 0; i < o.pingCount; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", address, o.probeTimeout)
		if err == nil {
			ok++
			total += time.Since(start)
			_ = conn.Close()
		}
	}
	if ok == 0 {
		return 0, 0
	}
	return ok, total / time.Duration(ok)
}

func quicPing(ip net.IP, o options, serverName string) (int, time.Duration) {
	var ok int
	var total time.Duration
	if serverName == "" {
		serverName = "cloudflare.com"
	}
	for i := 0; i < o.pingCount; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), o.probeTimeout)
		start := time.Now()
		probeConfig := newQUICConfig(o)
		probeConfig.HandshakeIdleTimeout = o.probeTimeout
		conn, err := quic.DialAddr(ctx, net.JoinHostPort(ip.String(), strconv.Itoa(o.port)), &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS13, NextProtos: []string{http3.NextProtoH3}}, probeConfig)
		cancel()
		if err == nil {
			ok++
			total += time.Since(start)
			_ = conn.CloseWithError(0, "")
		}
	}
	if ok == 0 {
		return 0, 0
	}
	return ok, total / time.Duration(ok)
}

func newQUICConfig(o options) *quic.Config {
	mib := uint64(1024 * 1024)
	streamMax := o.streamWindowMiB * mib
	connMax := o.connWindowMiB * mib
	streamInitial := uint64(2 * mib)
	connInitial := uint64(4 * mib)
	if streamInitial > streamMax {
		streamInitial = streamMax
	}
	if connInitial > connMax {
		connInitial = connMax
	}
	return &quic.Config{
		HandshakeIdleTimeout:           o.requestTimeout,
		InitialStreamReceiveWindow:     streamInitial,
		MaxStreamReceiveWindow:         streamMax,
		InitialConnectionReceiveWindow: connInitial,
		MaxConnectionReceiveWindow:     connMax,
	}
}

func scoreLatency(r result) time.Duration {
	best := time.Duration(1<<63 - 1)
	if r.TCPReceived > 0 && r.TCPAvg < best {
		best = r.TCPAvg
	}
	if r.QUICReceived > 0 && r.QUICAvg < best {
		best = r.QUICAvg
	}
	return best
}

func protocolOrder(i int) []string {
	switch i % 3 {
	case 0:
		return []string{"http1", "http2", "http3"}
	case 1:
		return []string{"http2", "http3", "http1"}
	default:
		return []string{"http3", "http1", "http2"}
	}
}

func measureProtocol(ip net.IP, protocol string, o options, serverName string) transfer {
	tr := transfer{Protocol: protocol}
	if serverName == "" {
		tr.Err = "测速 URL 缺少主机名"
		return tr
	}

	parsedURL, err := url.Parse(o.url)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Hostname() == "" {
		tr.Err = "无效的 HTTPS 测速 URL"
		return tr
	}
	var client *http.Client
	var cleanup func()
	var trace *httptrace.ClientTrace
	if protocol == "http3" {
		h3TLS := &tls.Config{
			RootCAs:    o.testRootCAs,
			ServerName: serverName,
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{http3.NextProtoH3},
		}
		h3tr := &http3.Transport{
			TLSClientConfig:    h3TLS,
			DisableCompression: true,
			QUICConfig:         newQUICConfig(o),
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				tlsConf := h3TLS.Clone()
				if tlsCfg != nil {
					tlsConf = tlsCfg.Clone()
					tlsConf.ServerName = serverName
					tlsConf.MinVersion = tls.VersionTLS13
					tlsConf.NextProtos = []string{http3.NextProtoH3}
				}
				return quic.DialAddr(ctx, net.JoinHostPort(ip.String(), strconv.Itoa(o.port)), tlsConf, cfg)
			},
		}
		client = &http.Client{Transport: h3tr, CheckRedirect: noRedirect}
		cleanup = func() { _ = h3tr.Close() }
	} else {
		var nextProtos []string
		forceH2 := protocol == "http2"
		switch protocol {
		case "http1":
			nextProtos = []string{"http/1.1"}
		case "http2":
			nextProtos = []string{"h2"}
		default:
			tr.Err = "未知测速协议：" + protocol
			return tr
		}
		tlsConfig := &tls.Config{
			RootCAs:    o.testRootCAs,
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
			NextProtos: nextProtos,
		}
		h1tr := &http.Transport{
			Proxy: nil, // 不读取 HTTP_PROXY / HTTPS_PROXY，确保拨号目标就是候选 IP。
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: o.requestTimeout, KeepAlive: 30 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(o.port)))
			},
			TLSClientConfig:       tlsConfig,
			TLSHandshakeTimeout:   o.requestTimeout,
			ResponseHeaderTimeout: o.requestTimeout,
			ForceAttemptHTTP2:     forceH2,
			DisableCompression:    true,
			IdleConnTimeout:       30 * time.Second,
		}
		client = &http.Client{Transport: h1tr, CheckRedirect: noRedirect}
		cleanup = func() { h1tr.CloseIdleConnections() }
		trace = &httptrace.ClientTrace{
			TLSHandshakeDone: func(state tls.ConnectionState, handshakeErr error) {
				if handshakeErr == nil {
					tr.ALPN = state.NegotiatedProtocol
				}
			},
		}
	}
	defer cleanup()

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	bodyStarted := time.Time{}
	var bodyTimer *time.Timer
	defer func() {
		if bodyTimer != nil {
			bodyTimer.Stop()
		}
	}()

	buf := make([]byte, readBufferSize)
	firstRequest := true
	for {
		if ctx.Err() != nil {
			break
		}
		requestStarted := time.Now()
		reqCtx := ctx
		if trace != nil {
			reqCtx = httptrace.WithClientTrace(reqCtx, trace)
		}
		req, reqErr := http.NewRequestWithContext(reqCtx, http.MethodGet, o.url, nil)
		if reqErr != nil {
			tr.Err = reqErr.Error()
			break
		}
		req.Header.Set("User-Agent", "CFST-DualBench/"+appVersion)
		req.Header.Set("Accept-Encoding", "identity")
		if ref := cloudflareSpeedReferer(parsedURL.Hostname()); ref != "" {
			req.Header.Set("Referer", ref)
		}

		// Per-request header timeout. The overall body window has its own timer.
		headerTimer := time.AfterFunc(o.requestTimeout, func() {
			cancel(errors.New("等待响应头超时"))
		})
		resp, doErr := client.Do(req)
		headerTimer.Stop()
		if doErr != nil {
			if errors.Is(context.Cause(ctx), errBodyWindowElapsed) {
				break
			}
			if ctx.Err() != nil {
				if cause := context.Cause(ctx); cause != nil {
					tr.Err = cause.Error()
				} else {
					tr.Err = "请求被取消"
				}
			} else {
				tr.Err = classifyError(doErr)
			}
			break
		}
		tr.Requests++
		if firstRequest {
			tr.TTFB = time.Since(requestStarted)
			firstRequest = false
		}
		tr.Status = resp.StatusCode
		tr.HTTPProto = resp.Proto
		if tr.ALPN == "" {
			tr.ALPN = inferALPN(resp)
		}
		tr.CFRay = resp.Header.Get("CF-Ray")
		tr.Colo = getColo(resp.Header)
		tr.ClientIP = firstNonEmpty(resp.Header.Get("cf-meta-ip"), resp.Header.Get("cf-meta-client-ip"))
		tr.City = firstNonEmpty(resp.Header.Get("city"), resp.Header.Get("cf-meta-city"))
		tr.Country = firstNonEmpty(resp.Header.Get("country"), resp.Header.Get("cf-meta-country"))
		tr.ASN = resp.Header.Get("asn")
		tr.Location = resp.Header.Get("Location")
		tr.ContentLength = resp.ContentLength

		var responseErrors []string
		if mismatch := protocolMismatch(protocol, resp); mismatch != "" {
			responseErrors = append(responseErrors, mismatch)
		}
		if resp.StatusCode != http.StatusOK {
			statusErr := fmt.Sprintf("HTTP 状态码 %d", resp.StatusCode)
			if tr.Location != "" {
				statusErr += "；Location=" + tr.Location
			}
			responseErrors = append(responseErrors, statusErr)
		}
		if len(responseErrors) > 0 {
			tr.Err = strings.Join(responseErrors, "；")
			_ = resp.Body.Close()
			break
		}

		if bodyStarted.IsZero() {
			bodyStarted = time.Now()
			bodyTimer = time.AfterFunc(o.downloadTime, func() {
				cancel(errBodyWindowElapsed)
			})
		}
		var responseBytes int64
		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				tr.Bytes += int64(n)
				responseBytes += int64(n)
			}
			if readErr != nil {
				_ = resp.Body.Close()
				if errors.Is(readErr, io.EOF) {
					if ctx.Err() != nil {
						break
					}
					if responseBytes == 0 {
						tr.Err = "HTTP 200 响应正文为空"
						break
					}
					// Small static files are fetched repeatedly until the configured body window ends.
					// This prevents a short object from producing a misleading sub-second ranking.
					break
				}
				if ctx.Err() == nil {
					tr.Err = readErr.Error()
				}
				break
			}
			if ctx.Err() != nil {
				_ = resp.Body.Close()
				break
			}
		}
		if ctx.Err() != nil || tr.Err != "" {
			break
		}
		// EOF on a finite object: issue another GET on the same isolated client/connection pool.
		// This is part of the timed body window, so request overhead is included in throughput.
	}

	if !bodyStarted.IsZero() {
		tr.Elapsed = time.Since(bodyStarted)
	}
	if tr.Elapsed > 0 {
		tr.SpeedMiB = float64(tr.Bytes) / tr.Elapsed.Seconds() / (1024 * 1024)
	}
	if tr.Bytes == 0 && tr.Err == "" {
		tr.Err = "响应正文没有数据"
	}
	if tr.Elapsed < o.downloadTime/2 && tr.Err == "" {
		tr.Err = fmt.Sprintf("测速样本不足：实际正文阶段仅 %s，目标 %s", tr.Elapsed, o.downloadTime)
	}
	return tr
}

var errBodyWindowElapsed = errors.New("测速正文时间窗口结束")

func protocolMismatch(protocol string, resp *http.Response) string {
	if resp == nil {
		return "没有收到 HTTP 响应"
	}
	want := ""
	ok := false
	switch protocol {
	case "http1":
		want = "HTTP/1.1"
		ok = resp.ProtoMajor == 1 && resp.ProtoMinor == 1
	case "http2":
		want = "HTTP/2"
		ok = resp.ProtoMajor == 2
	case "http3":
		want = "HTTP/3"
		ok = resp.ProtoMajor == 3
	default:
		return "未知的协议类型：" + protocol
	}
	if ok {
		return ""
	}
	actual := resp.Proto
	if actual == "" {
		actual = fmt.Sprintf("HTTP/%d.%d", resp.ProtoMajor, resp.ProtoMinor)
	}
	return fmt.Sprintf("协议协商不匹配：要求 %s，实际 %s；该结果不计入排名", want, actual)
}

func inferALPN(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	switch resp.ProtoMajor {
	case 1:
		return "http/1.1"
	case 2:
		return "h2"
	case 3:
		return http3.NextProtoH3
	default:
		return ""
	}
}

func cloudflareSpeedReferer(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "speed.cloudflare.com" || strings.HasSuffix(host, ".speed.cloudflare.com") {
		return "https://" + host + "/"
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func noRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
func classifyError(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "请求或响应头等待超时/被取消"
	}
	return err.Error()
}
func getColo(h http.Header) string {
	if colo := firstNonEmpty(h.Get("colo"), h.Get("cf-meta-colo")); colo != "" {
		return strings.ToUpper(colo)
	}
	if ray := h.Get("CF-Ray"); ray != "" {
		parts := strings.Split(ray, "-")
		if len(parts) > 1 {
			return strings.ToUpper(parts[len(parts)-1])
		}
	}
	return ""
}
func coloOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func writeOutputs(rows []result, o options) error {
	if err := os.MkdirAll(o.outDir, 0755); err != nil {
		return err
	}
	eligible := func(colo string) bool { return o.coloFilter == "" || strings.EqualFold(colo, o.coloFilter) }

	tcpRows := append([]result(nil), rows...)
	sort.Slice(tcpRows, func(i, j int) bool { return validSpeed(tcpRows[i].H1) > validSpeed(tcpRows[j].H1) })
	h2Rows := append([]result(nil), rows...)
	sort.Slice(h2Rows, func(i, j int) bool { return validSpeed(h2Rows[i].H2) > validSpeed(h2Rows[j].H2) })
	h3Rows := append([]result(nil), rows...)
	sort.Slice(h3Rows, func(i, j int) bool { return validSpeed(h3Rows[i].H3) > validSpeed(h3Rows[j].H3) })
	cmpRows := append([]result(nil), rows...)
	sort.Slice(cmpRows, func(i, j int) bool { return validSpeed(cmpRows[i].H3) > validSpeed(cmpRows[j].H3) })

	if err := writeProtocolCSV(filepath.Join(o.outDir, "result-tcp.csv"), tcpRows, "http1", eligible); err != nil {
		return err
	}
	if err := writeProtocolCSV(filepath.Join(o.outDir, "result-h2.csv"), h2Rows, "http2", eligible); err != nil {
		return err
	}
	if err := writeProtocolCSV(filepath.Join(o.outDir, "result-h3.csv"), h3Rows, "http3", eligible); err != nil {
		return err
	}
	if err := writeCompareCSV(filepath.Join(o.outDir, "result-compare.csv"), cmpRows, o); err != nil {
		return err
	}
	return writeDiagnosticsCSV(filepath.Join(o.outDir, "result-diagnostics.csv"), rows)
}

func writeProtocolCSV(path string, rows []result, protocol string, eligible func(string) bool) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write([]string{"IP", "ConnectOrHandshake_ms", "Handshake_Successes", "Handshake_Attempts", "Download_MiBps", "Bytes", "BodyElapsed_ms", "TTFB_ms", "HTTP_Status", "HTTP_Protocol", "ALPN", "Requests", "Content_Length", "CF_Colo", "CF_Client_IP", "CF_City", "CF_Country", "CF_ASN", "CF_Ray", "Location", "Error"}); err != nil {
		return err
	}
	for _, r := range rows {
		var t transfer
		var avg time.Duration
		var recv, total int
		switch protocol {
		case "http1":
			t, avg, recv, total = r.H1, r.TCPAvg, r.TCPReceived, r.TCPTotal
		case "http2":
			t, avg, recv, total = r.H2, r.TCPAvg, r.TCPReceived, r.TCPTotal
		case "http3":
			t, avg, recv, total = r.H3, r.QUICAvg, r.QUICReceived, r.QUICTotal
		}
		// Ranking files contain only verified successful samples. Failed or downgraded
		// protocol attempts remain visible in result-diagnostics.csv.
		if !eligible(t.Colo) || t.Err != "" || t.SpeedMiB <= 0 {
			continue
		}
		if err := w.Write([]string{r.IP.String(), fmtMS(avg), strconv.Itoa(recv), strconv.Itoa(total), fmtFloat(t.SpeedMiB), strconv.FormatInt(t.Bytes, 10), fmtMS(t.Elapsed), fmtMS(t.TTFB), strconv.Itoa(t.Status), t.HTTPProto, t.ALPN, strconv.Itoa(t.Requests), strconv.FormatInt(t.ContentLength, 10), t.Colo, t.ClientIP, t.City, t.Country, t.ASN, t.CFRay, t.Location, t.Err}); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return nil
}

func writeCompareCSV(path string, rows []result, o options) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	header := []string{
		"IP", "TCP_Connect_ms", "TCP_Successes", "TCP_Attempts", "QUIC_Handshake_ms", "QUIC_Successes", "QUIC_Attempts",
		"HTTP1_MiBps", "HTTP1_Status", "HTTP1_Protocol", "HTTP1_ALPN", "HTTP1_TTFB_ms", "HTTP1_Colo", "HTTP1_Error",
		"HTTP2_MiBps", "HTTP2_Status", "HTTP2_Protocol", "HTTP2_ALPN", "HTTP2_TTFB_ms", "HTTP2_Colo", "HTTP2_Error",
		"HTTP3_MiBps", "HTTP3_Status", "HTTP3_Protocol", "HTTP3_ALPN", "HTTP3_TTFB_ms", "HTTP3_Colo", "HTTP3_Error",
	}
	if err := w.Write(header); err != nil {
		return err
	}
	for _, r := range rows {
		if o.coloFilter != "" && !anyProtocolMatchesColo(r, o.coloFilter) {
			continue
		}
		rec := []string{
			r.IP.String(), fmtMS(r.TCPAvg), strconv.Itoa(r.TCPReceived), strconv.Itoa(r.TCPTotal), fmtMS(r.QUICAvg), strconv.Itoa(r.QUICReceived), strconv.Itoa(r.QUICTotal),
			fmtFloat(validSpeed(r.H1)), strconv.Itoa(r.H1.Status), r.H1.HTTPProto, r.H1.ALPN, fmtMS(r.H1.TTFB), r.H1.Colo, r.H1.Err,
			fmtFloat(validSpeed(r.H2)), strconv.Itoa(r.H2.Status), r.H2.HTTPProto, r.H2.ALPN, fmtMS(r.H2.TTFB), r.H2.Colo, r.H2.Err,
			fmtFloat(validSpeed(r.H3)), strconv.Itoa(r.H3.Status), r.H3.HTTPProto, r.H3.ALPN, fmtMS(r.H3.TTFB), r.H3.Colo, r.H3.Err,
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return nil
}

func validSpeed(t transfer) float64 {
	if t.Err != "" {
		return 0
	}
	return t.SpeedMiB
}

func anyProtocolMatchesColo(r result, filter string) bool {
	return eligibleColo(r.H1.Colo, filter) && r.H1.Colo != "" ||
		eligibleColo(r.H2.Colo, filter) && r.H2.Colo != "" ||
		eligibleColo(r.H3.Colo, filter) && r.H3.Colo != ""
}

func eligibleColo(colo, filter string) bool { return filter == "" || strings.EqualFold(colo, filter) }

func writeDiagnosticsCSV(path string, rows []result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	header := []string{
		"IP", "TCP_Successes", "TCP_Attempts", "TCP_Connect_ms", "QUIC_Successes", "QUIC_Attempts", "QUIC_Handshake_ms",
		"HTTP1_Status", "HTTP1_Protocol", "HTTP1_ALPN", "HTTP1_TTFB_ms", "HTTP1_Bytes", "HTTP1_Body_ms", "HTTP1_Colo", "HTTP1_Client_IP", "HTTP1_City", "HTTP1_Country", "HTTP1_ASN", "HTTP1_CF_Ray", "HTTP1_Requests", "HTTP1_Content_Length", "HTTP1_Location", "HTTP1_Error",
		"HTTP2_Status", "HTTP2_Protocol", "HTTP2_ALPN", "HTTP2_TTFB_ms", "HTTP2_Bytes", "HTTP2_Body_ms", "HTTP2_Colo", "HTTP2_Client_IP", "HTTP2_City", "HTTP2_Country", "HTTP2_ASN", "HTTP2_CF_Ray", "HTTP2_Requests", "HTTP2_Content_Length", "HTTP2_Location", "HTTP2_Error",
		"HTTP3_Status", "HTTP3_Protocol", "HTTP3_ALPN", "HTTP3_TTFB_ms", "HTTP3_Bytes", "HTTP3_Body_ms", "HTTP3_Colo", "HTTP3_Client_IP", "HTTP3_City", "HTTP3_Country", "HTTP3_ASN", "HTTP3_CF_Ray", "HTTP3_Requests", "HTTP3_Content_Length", "HTTP3_Location", "HTTP3_Error",
	}
	if err := w.Write(header); err != nil {
		return err
	}
	for _, r := range rows {
		rec := []string{
			r.IP.String(), strconv.Itoa(r.TCPReceived), strconv.Itoa(r.TCPTotal), fmtMS(r.TCPAvg), strconv.Itoa(r.QUICReceived), strconv.Itoa(r.QUICTotal), fmtMS(r.QUICAvg),
			strconv.Itoa(r.H1.Status), r.H1.HTTPProto, r.H1.ALPN, fmtMS(r.H1.TTFB), strconv.FormatInt(r.H1.Bytes, 10), fmtMS(r.H1.Elapsed), r.H1.Colo, r.H1.ClientIP, r.H1.City, r.H1.Country, r.H1.ASN, r.H1.CFRay, strconv.Itoa(r.H1.Requests), strconv.FormatInt(r.H1.ContentLength, 10), r.H1.Location, r.H1.Err,
			strconv.Itoa(r.H2.Status), r.H2.HTTPProto, r.H2.ALPN, fmtMS(r.H2.TTFB), strconv.FormatInt(r.H2.Bytes, 10), fmtMS(r.H2.Elapsed), r.H2.Colo, r.H2.ClientIP, r.H2.City, r.H2.Country, r.H2.ASN, r.H2.CFRay, strconv.Itoa(r.H2.Requests), strconv.FormatInt(r.H2.ContentLength, 10), r.H2.Location, r.H2.Err,
			strconv.Itoa(r.H3.Status), r.H3.HTTPProto, r.H3.ALPN, fmtMS(r.H3.TTFB), strconv.FormatInt(r.H3.Bytes, 10), fmtMS(r.H3.Elapsed), r.H3.Colo, r.H3.ClientIP, r.H3.City, r.H3.Country, r.H3.ASN, r.H3.CFRay, strconv.Itoa(r.H3.Requests), strconv.FormatInt(r.H3.ContentLength, 10), r.H3.Location, r.H3.Err,
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return nil
}
func fmtMS(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return fmt.Sprintf("%.2f", float64(d)/float64(time.Millisecond))
}
func fmtFloat(v float64) string {
	if v <= 0 {
		return ""
	}
	return fmt.Sprintf("%.3f", v)
}
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "错误："+format+"\n", args...)
	os.Exit(1)
}
