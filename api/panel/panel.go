package panel

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/InazumaV/V2bX/conf"
	"github.com/go-resty/resty/v2"
)

// Panel is the interface for different panel's api.

type Client struct {
	client           *resty.Client
	APIHost          string
	APISendIP        string
	Token            string
	NodeType         string
	NodeId           int
	nodeEtag         string
	userEtag         string
	responseBodyHash string
	UserList         *UserListBody
	AliveMap         *AliveMap
}

func New(c *conf.ApiConfig) (*Client, error) {
	var client *resty.Client
	if c.APISendIP != "" {
		client = resty.NewWithLocalAddr(&net.TCPAddr{
			IP: net.ParseIP(c.APISendIP),
		})
	} else {	
		client = resty.New()
	}
	client.SetRetryCount(3)
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			logrus.Error(v.Err)
		}
	})
	client.SetBaseURL(c.APIHost)
	if maxVer, err := parseTLSMaxVersion(c.TlsMaxVersion); err != nil {
		return nil, err
	} else if maxVer != 0 {
		client.SetTLSClientConfig(&tls.Config{MaxVersion: maxVer})
		logrus.Infof("panel HTTPS client forcing TLS 1.2, host=%s node_id=%d", c.APIHost, c.NodeID)
	}
	// Check node type
	c.NodeType = strings.ToLower(c.NodeType)
	switch c.NodeType {
	case "v2ray":
		c.NodeType = "vmess"
	case
		"vmess",
		"trojan",
		"shadowsocks",
		"hysteria",
		"hysteria2",
		"tuic",
		"anytls",
		"vless":
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	// set params
	client.SetQueryParams(map[string]string{
		"node_type": c.NodeType,
		"node_id":   strconv.Itoa(c.NodeID),
		"token":     c.Key,
	})
	return &Client{
		client:    client,
		Token:     c.Key,
		APIHost:   c.APIHost,
		APISendIP: c.APISendIP,
		NodeType:  c.NodeType,
		NodeId:    c.NodeID,
		UserList:  &UserListBody{},
		AliveMap:  &AliveMap{},
	}, nil
}

func parseTLSMaxVersion(v string) (uint16, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "1.3", "tls1.3", "tlsv1.3":
		return 0, nil
	case "1.2", "tls1.2", "tlsv1.2":
		return tls.VersionTLS12, nil
	default:
		return 0, fmt.Errorf("unsupported TlsMaxVersion %q (use 1.2 or 1.3)", v)
	}
}
