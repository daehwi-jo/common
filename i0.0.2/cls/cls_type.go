package cls

import "net"

type NSTATE uint
type PROTOCOL uint
type FORWARD uint
type RESULT int

// return state
const (
	CONF_ERR RESULT = -1
	CONF_NET        = -2
	CONF_OK         = iota
)

// service type (protocol type)
const (
	PROTOCOL_NONE PROTOCOL = iota
	UDP_ECHO
	UDP_DNS
	UDP_TLV
	UDP
	TCP
	TCP_TLV
	TCP_DNS
	TCP_ECHO
	TCP_STATION
	TCP_FILE
	TCP_SPHERE
	TCP_HTTP
	TCP_HTTPS
	CLIENT
	TCP_CLIENT
	TCP_CLIENT_C
	UDP_CLIENT
	HTTP
	HTTPS
	LOCAL_HOST
)

// server select method
const (
	RR FORWARD = iota
	AS
	TT
	NO
)

// network state
const (
	AC_CLIENT NSTATE = iota
	CK_CLIENT
	RD_CLIENT
	WR_CLIENT
	CO_SERVER
	CK_SERVER
	RD_SERVER
	WR_SERVER
	ER_SERVER
	CK_TIMER
)

const MAX_ONE_PACKET = 1024
const MAX_RETRY_COUNT = 2

// http request type
const (
	GET int = iota
	PUT
	DEL
	POST
	PAGE
	LOGIN
	LOGOUT
	EXCEPT
)

// query type
const (
	SELECT int = iota
	UPDATE
	INSERT
	DELETE
)

// request status
const (
	REQ_START RESULT = iota
	REQ_FINISH
)

// query set
type QuerySet struct {
	Qtype int
	Qname string
	Query string
}

type WebData map[string]string

// application function
type App_data func(ad *AppdataInfo) int

func AppHandler(Handler App_data, ad *AppdataInfo) int {
	return Handler(ad)
}

// server infomation
type ServerInfo struct {
	ipaddr   string
	port     uint
	protocol PROTOCOL
	service  PROTOCOL

	headerSize uint

	healthPeriod uint
	healthStime  uint
	healthPage   string

	fd             uint
	cfgIdx         uint
	forwardType    FORWARD
	used           uint
	originPriority uint
	nowPriority    uint

	sslBool     bool
	requeryBool bool
	remoteType  string

	sessionMax uint
	clientMax  uint

	aclList []string
}

// multi forward :  server list array
type MultiServer struct {
	forwardServers []ServerInfo
}

// server INFO data
type CfgServer struct {
	serverInfo   ServerInfo
	multiServers []MultiServer
}

// application communicate data
type AppdataInfo struct {
	NState  NSTATE // communication state
	Service PROTOCOL

	Client IndataInfo // client data
	Server IndataInfo // server data

	coClient net.Conn
	coTcpSvr net.Conn
	coUdpSvr *net.UDPConn

	ResBool bool // response 여부
	forType uint // forward 시 타입

	Appdata interface{}
	Adidata int
}

// network data
type IndataInfo struct {
	Proto   PROTOCOL
	Rbuf    []byte // recv data
	Rheader []byte // recv header
	Rlen    int    // recv len
	Tlen    int    // recv total len
	Sbuf    []byte // send data
	Slen    int    // send len
}
