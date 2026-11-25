package task

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/XIU2/CloudflareSpeedTest/utils"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	quicHandshakeTimeout = 1500 * time.Millisecond
	defaultQUICSNI       = "cloudflare.com"
)

var (
	Quicing bool
	HTTP3   bool
)

func getQUICServerName() string {
	u, err := url.Parse(URL)
	if err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return defaultQUICSNI
}

func newQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: quicHandshakeTimeout,
	}
}

func getQUICDial(ip *net.IPAddr) func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	targetAddr := net.JoinHostPort(ip.String(), strconv.Itoa(TCPPort))
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		var tlsConf *tls.Config
		if tlsCfg != nil {
			tlsConf = tlsCfg.Clone()
		} else {
			tlsConf = &tls.Config{ServerName: getQUICServerName()}
		}
		if len(tlsConf.NextProtos) == 0 {
			tlsConf.NextProtos = []string{http3.NextProtoH3}
		}
		return quic.DialAddr(ctx, targetAddr, tlsConf, cfg)
	}
}

func newHTTP3Transport(ip *net.IPAddr) *http3.Transport {
	return &http3.Transport{
		Dial:       getQUICDial(ip),
		QUICConfig: newQUICConfig(),
	}
}

func (p *Ping) quicPingOnce(ip *net.IPAddr, serverName string) (bool, time.Duration, error) {
	targetAddr := net.JoinHostPort(ip.String(), strconv.Itoa(TCPPort))
	ctx, cancel := context.WithTimeout(context.Background(), quicHandshakeTimeout)
	defer cancel()

	tlsConf := &tls.Config{
		ServerName: serverName,
		NextProtos: []string{http3.NextProtoH3},
	}

	startTime := time.Now()
	conn, err := quic.DialAddr(ctx, targetAddr, tlsConf, newQUICConfig())
	if err != nil {
		return false, 0, err
	}
	duration := time.Since(startTime)
	_ = conn.CloseWithError(0, "")
	return true, duration, nil
}

// quicing performs pure QUIC handshake latency tests over UDP.
func (p *Ping) quicing(ip *net.IPAddr) (recv int, totalDelay time.Duration) {
	serverName := getQUICServerName()
	for i := 0; i < PingTimes; i++ {
		ok, delay, err := p.quicPingOnce(ip, serverName)
		if ok {
			recv++
			totalDelay += delay
		} else if utils.Debug && i == 0 {
			utils.Red.Printf("[调试] IP: %s, QUIC 握手失败，错误信息: %v, 端口: %d\n", ip.String(), err, TCPPort)
		}
	}
	return
}
