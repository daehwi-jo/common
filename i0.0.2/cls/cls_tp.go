package cls

import "net"
import "fmt"
import "time"
import "strings"

// server 인 경우 listen 시작
// client 연결형인 경우 connect 시작
func tpConStart(app App_data) {

	fmt.Print("CONNECTION START : ", len(CfgServers), "\n")
	for i := 0; i < len(CfgServers); i++ {
		if CfgServers[i].serverInfo.service < CLIENT {
			fmt.Print("go tp listen START : ", i, "\n")
			go tpListen(CfgServers[i].serverInfo, app)
		} else if CfgServers[i].serverInfo.service == TCP_CLIENT_C {
			fmt.Print("go tp connect START : ", i, "\n")
			go tpConnect(CfgServers[i].serverInfo, app, nil, 0)
		}
	}

	/*
		var ad AppdataInfo

		for {
			// timer
			time.Sleep(10)
			ad.NState = CK_TIMER
			r := AppHandler(app, &ad)
			if r < 0 {
				fmt.Print("state CO_SERVER application return err\n")
			}
		}*/
}
func tpConStart_idle(app App_data, listenIP string) {

	fmt.Print("CONNECTION START : ", len(CfgServers), "\n")
	for i := 0; i < len(CfgServers); i++ {
		if CfgServers[i].serverInfo.service < CLIENT {
			fmt.Print("go tp listen START : ", i, "\n")
			go tpListen_idle(CfgServers[i].serverInfo, app, listenIP)
		} else if CfgServers[i].serverInfo.service == TCP_CLIENT_C {
			fmt.Print("go tp connect START : ", i, "\n")
			go tpConnect(CfgServers[i].serverInfo, app, nil, 0)
		}
	}

}

func tpConStartSvc(app App_data, stopChan chan int) {
	var ad AppdataInfo
	var pause int

	fmt.Print("CONNECTION START : ", len(CfgServers), "\n")
	for i := 0; i < len(CfgServers); i++ {
		if CfgServers[i].serverInfo.service < CLIENT {
			fmt.Print("go tp listen START : ", i, "\n")
			go tpListen(CfgServers[i].serverInfo, app)
		} else if CfgServers[i].serverInfo.service == TCP_CLIENT_C {
			fmt.Print("go tp connect START : ", i, "\n")
			go tpConnect(CfgServers[i].serverInfo, app, nil, 0)
		}
	}

	for {
		select {
		case msg := <-stopChan:
			if msg == 1 { //stop
				return
			} else if msg == 2 { //pause
				pause = 1
			} else if msg == 3 { //continue
				pause = 0
			}

		default: // timer
			time.Sleep(10)
			ad.NState = CK_TIMER
			if pause != 1 && AppHandler(app, &ad) < 0 {
				fmt.Print("state CO_SERVER application return err\n")
			}
		} // select
	}
}

// application에서 client로 server에 연결 시도
func ConnectServer(idx int, sType PROTOCOL, app App_data, adata interface{}, adidata int) {
	var maxPri, maxIdx, totalPri uint
	var fss []ServerInfo

	// find forward service
	for i := 0; i < len(CfgServers[idx].multiServers); i++ {
		fss = CfgServers[idx].multiServers[i].forwardServers
		if fss[0].service == sType {
			break
		}
	}

	if CfgServers[idx].serverInfo.forwardType == AS {
	} else if CfgServers[idx].serverInfo.forwardType == RR {
		// select max priority server
		for i := 0; i < len(fss); i++ {
			fsi := fss[i]
			totalPri += fsi.nowPriority
			if fsi.nowPriority > maxPri {
				maxPri = fsi.nowPriority
				maxIdx = uint(i)
			}
		}

		// select forward server and reduce priority
		fss[maxIdx].nowPriority -= 1
		totalPri -= 1

		// recharge priroity
		if totalPri == 0 {
			for i := 0; i < len(fss); i++ {
				fss[i].nowPriority = fss[i].originPriority
			}
		}
		tpConnect(fss[maxIdx], app, adata, adidata)
	}

	return
}

// client로 server에 연결 시도
func tpConnect(si ServerInfo, app App_data, adata interface{}, adidata int) {
	var ad AppdataInfo
	var con net.Conn
	var err error

	//id := &ad.server
	fs, _, _ := selServer(si, si.service)
	addr := fmt.Sprintf("%s:%d", fs.ipaddr, fs.port)

	if fs.protocol >= TCP {
		con, err = net.Dial("tcp", addr)
		if err != nil {
			fmt.Println("err", err)
			return
		}
	} else {
		con, err = net.Dial("udp", addr)
	}
	defer con.Close()

	ad.Service = si.service
	ad.NState = CO_SERVER
	ad.coClient = con
	ad.Appdata = adata
	ad.Adidata = adidata

	r := AppHandler(app, &ad)
	if r < 0 {
		fmt.Print("state CO_SERVER application return err\n")
	}

	// read or write
	if ad.ResBool {
		return
	} else {
		tpFClient(si, &ad, app)
	}
	return
}

// liste 대기중 client 접속 시 server 동작
func tpListen(si ServerInfo, app App_data) {

	// addr := fmt.Sprintf(":%d", si.port)
	addr := fmt.Sprintf("%s:%d", ListenIP, si.port)

	if si.protocol >= TCP {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			fmt.Print(err)
		}
		defer listener.Close()

		fmt.Print("LISTEN TCP : ", addr, "\n")
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go tpTcpServer(si, conn, app)
		}

	} else {
		fmt.Print("LISTEN UDP : ", addr, "\n")
		ServerAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			fmt.Print(err)
			return
		}

		conn, err := net.ListenUDP("udp", ServerAddr)
		if err != nil {
			fmt.Print(err)
			return
		}
		defer conn.Close()

		for {
			rbuf := make([]byte, MAX_ONE_PACKET)
			rlen, addr, err := conn.ReadFromUDP(rbuf)
			if err != nil {
				fmt.Print("state CK_CLIENT UDP read fail")
				continue
			}

			go tpUdpServer(si, conn, addr, rbuf, rlen, app)
		}
	}
}
func tpListen_idle(si ServerInfo, app App_data, listenIP string) {

	// addr := fmt.Sprintf(":%d", si.port)

	if si.protocol >= TCP {
		addr := fmt.Sprintf("%s:%d", ListenIP, si.port)

		listener, err := net.Listen("tcp", addr)
		if err != nil {
			fmt.Print(err)
		}
		defer listener.Close()

		fmt.Print("LISTEN TCP test : ", addr, "\n")
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go tpTcpServer(si, conn, app)
		}

	} else {
		addr := fmt.Sprintf("%s:%d", listenIP, si.port)

		fmt.Print("LISTEN UDP : ", addr, "\n")
		Lprintf(4, "[INFO] LISTEN UDP (%s)", addr)
		ServerAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			fmt.Print(err)
			return
		}

		conn, err := net.ListenUDP("udp", ServerAddr)
		if err != nil {
			fmt.Print(err)
			return
		}
		defer conn.Close()

		for {
			rbuf := make([]byte, MAX_ONE_PACKET)
			rlen, addr, err := conn.ReadFromUDP(rbuf)
			if err != nil {
				fmt.Print("state CK_CLIENT UDP read fail")
				continue
			}

			go tpUdpServer(si, conn, addr, rbuf, rlen, app)
		}
	}
}

// server 로 동작
// tcp 인 경우 header 만큼 읽은 후 app으로 부터 ck 확인 후 나머지 read
func tpTcpServer(si ServerInfo, co net.Conn, app App_data) {
	var ad AppdataInfo
	var err error

	Lprintf(4, "[INFO] TCP SERVER ACCEPTED ")
	ad.Service = si.service
	id := &ad.Client

	id.Rlen = int(si.headerSize)
	if si.headerSize == 0 {
		id.Rlen = MAX_ONE_PACKET
	}

	id.Rheader = make([]byte, id.Rlen)
	id.Rlen, err = co.Read(id.Rheader)
	if err != nil {
		Lprintf(1, "[FAIL] state CK_CLIENT TCP read fail")
		co.Close()
		return
	}

	ad.NState = CK_CLIENT
	ad.coTcpSvr = co
	id.Proto = si.protocol

	r := AppHandler(app, &ad)
	if r < 0 {
		Lprintf(1, "[FAIL] state CK_CLIENT application return err")
		co.Close()
		return
	}

	if id.Tlen != id.Rlen {
		mlen := id.Tlen - id.Rlen
		mbuf := make([]byte, mlen)
		mlen, err = co.Read(mbuf)
		if err != nil {
			Lprintf(1, "[FAIL] state after CK_CLIENT TCP more read fail")
			co.Close()
			return
		}
		id.Rbuf = make([]byte, id.Tlen)
		id.Rbuf = append(id.Rheader, mbuf[:mlen]...)
		id.Rlen = id.Tlen
	} else {
		id.Rbuf = id.Rheader
	}

	ad.NState = RD_CLIENT
	r = AppHandler(app, &ad)
	if r < 0 {
		fmt.Print("state RD_CLIENT application return err")
		co.Close()
		return
	}

	// response 여부에 따라 client에 답하거나 forward
	for ad.ResBool != true {
		retry := MAX_RETRY_COUNT
		for tpFClient(si, &ad, app) < 0 {
			retry -= 1
			if retry == 0 {
				ad.NState = ER_SERVER
				if AppHandler(app, &ad) < 0 {
					Lprintf(1, "[FAIL] state ER_SERVER application return err")
					goto fail
				}
				break
			}
		}
	}

	co.Write(id.Sbuf)

fail:
	co.Close()

	return
}

func tpUdpServer(si ServerInfo, co *net.UDPConn, addr *net.UDPAddr, rbuf []byte, rlen int, app App_data) {
	var ad AppdataInfo

	id := &ad.Client
	id.Rlen = rlen
	id.Rbuf = rbuf
	id.Proto = si.protocol

	Lprintf(4, "[INFO] UDP DATA RECEIVED")
	LprintPacket(4, id.Rbuf, id.Rlen)

	ad.NState = RD_CLIENT
	ad.coUdpSvr = co
	ad.Service = si.service

	r := AppHandler(app, &ad)
	if r < 0 {
		Lprintf(1, "[FAIL] state RD_CLIENT application return err")
		return
	}

	// response 여부에 따라 client에 답하거나 forward
	for ad.ResBool != true {

		retry := MAX_RETRY_COUNT
		for tpFClient(si, &ad, app) < 0 {
			retry -= 1
			if retry == 0 {
				ad.NState = ER_SERVER
				if AppHandler(app, &ad) < 0 {
					Lprintf(1, "[FAIL] state ER_SERVER application return err")
					return
				}
				break
			}
		}
	}

	co.WriteToUDP(id.Sbuf, addr)

	return
}

func reorder(k int, ips []string) string {

	addr := ips[k]
	k++
	if k == len(ips)-1 {
		k = 0
	}

	for i := 0; i < len(ips)-1; i++ {
		addr += "&" + ips[k]
		k++
		if k == len(ips)-1 {
			k = 0
		}
	}

	return addr
}

func conASDialTcp(ips []string, port, sidx, midx, fidx uint) (net.Conn, error) {

	var con net.Conn
	var err error

	for i := 0; i < len(ips); i++ {
		addr := fmt.Sprintf("%s:%d", ips[0], port)
		con, err = net.DialTimeout("tcp", addr, time.Duration(10)*time.Second)
		if err == nil {
			Lprintf(4, "[INFO] connection succ(%d):(%s)", i, addr)
			if i != 0 {
				Lprintf(4, "[INFO] forward server re order (%d):(%s)", i, addr)
				CfgServers[sidx].multiServers[midx].forwardServers[fidx].ipaddr = reorder(i, ips)
			}
			break
		}
		Lprintf(4, "[INFO] connection fail(%d):(%s)->(%s)", i, addr, err)
	}
	return con, err
}

// forward data as a client
func tpFClient(si ServerInfo, ad *AppdataInfo, app App_data) int {

	//var con net.Conn
	var err error

	fs, midx, fidx := selServer(si, si.service)
	id := &ad.Server
	con := ad.coClient
	ips := strings.Split(fs.ipaddr, "&") // split tokens <= line

	Lprintf(4, "[INFO] forward server info (%s) Send data", fs.ipaddr)
	LprintPacket(4, id.Sbuf, id.Slen)

	if fs.protocol >= TCP && fs.service != TCP_TLV {
		if con == nil {
			if len(ips) > 1 {
				con, err = conASDialTcp(ips, fs.port, si.cfgIdx, midx, fidx)
			} else {
				addr := fmt.Sprintf("%s:%d", fs.ipaddr, fs.port)
				con, err = net.Dial("tcp", addr)
			}

			if err != nil {
				fmt.Println("err", err)
				return (-1)
			}
			defer con.Close()
		}

		con.Write(id.Sbuf)
		id.Rlen = int(fs.headerSize)
		if fs.headerSize == 0 {
			id.Rlen = MAX_ONE_PACKET
		}

		id.Rheader = make([]byte, id.Rlen)
		id.Rlen, err = con.Read(id.Rheader)
		if err != nil {
			Lprintf(1, "[FAIL] state CK_SERVER read fail")
			return (-1)
		}
		ad.NState = CK_SERVER

		r := AppHandler(app, ad)
		if r < 0 {
			Lprintf(1, "[FAIL] state CK_SERVER application return err")
		}

		if id.Tlen != id.Rlen {
			mlen := id.Tlen - id.Rlen
			mbuf := make([]byte, mlen)
			con.Read(mbuf)
			id.Rbuf = append(id.Rheader, mbuf[:mlen]...)
			id.Rlen = id.Tlen
		} else {
			id.Rbuf = id.Rheader[:id.Tlen]
		}

	} else {
		if con == nil {
			addr := fmt.Sprintf("%s:%d", fs.ipaddr, fs.port)
			con, err = net.Dial("udp", addr)
		}
		con.Write(id.Sbuf)

		id.Rbuf = make([]byte, MAX_ONE_PACKET)
		id.Rlen, err = con.Read(id.Rbuf)
		if err != nil {
			Lprintf(1, "[FAIL] state CK_SERVER read fail")
			return (-1)
		}
	}

	ad.NState = RD_SERVER
	r := AppHandler(app, ad)
	if r < 0 {
		Lprintf(1, "[FAIL] state RD_SERVER application return err")
		return (-1)
	}

	return 0
}

func selServer(si ServerInfo, sType PROTOCOL) (ServerInfo, uint, uint) {
	var maxPri, maxIdx, totalPri uint
	var fss []ServerInfo
	var idx uint

	// find forward service
	for i := 0; i < len(CfgServers[si.cfgIdx].multiServers); i++ {
		fss = CfgServers[si.cfgIdx].multiServers[i].forwardServers
		if fss[0].service == sType {
			idx = uint(i)
			break
		}
	}

	//	if CfgServers[si.cfgIdx].serverInfo.forwardType == AS {
	//		return fss[CfgServers[si.cfgIdx].serverInfo.used]
	//	} else {
	// select max priority server
	for i := 0; i < len(fss); i++ {
		fsi := fss[i]
		if fsi.used == 0 {
			continue
		}

		totalPri += fsi.nowPriority
		if fsi.nowPriority > maxPri {
			maxPri = fsi.nowPriority
			maxIdx = uint(i)
		}
	}

	// select forward server and reduce priority
	fss[maxIdx].nowPriority -= 1
	totalPri -= 1

	// recharge priroity
	if totalPri == 0 {
		for i := 0; i < len(fss); i++ {
			fss[i].nowPriority = fss[i].originPriority
		}
	}

	return fss[maxIdx], idx, maxIdx
	//	}
}

func testRRServer(server ServerInfo) uint {
	addr := fmt.Sprintf("%s:%d", server.ipaddr, server.port)
	con, err := net.Dial("tcp", addr)
	if err == nil {
		con.Close()
		return uint(1)
	}
	return uint(0)
}

func testASServer(servers []ServerInfo, sel uint) uint {
	cnt := uint(len(servers))
	for i := uint(0); i < cnt; i++ {
		sel = (sel + i) % cnt
		addr := fmt.Sprintf("%s:%d", servers[sel].ipaddr, servers[sel].port)
		con, err := net.Dial("tcp", addr)
		if err == nil {
			con.Close()
			return sel
		}
	}
	return 0
}

func healthCheck(idx uint, period int) {
	for {
		time.Sleep(time.Duration(period) * time.Second)
		// multi server 가 있는 경우 multi 까지
		for i := 0; i < len(CfgServers[idx].multiServers); i++ {
			fss := CfgServers[idx].multiServers[i].forwardServers

			// tcp connection 만 확인 한다.
			if fss[0].protocol < TCP {
				continue
			}

			if CfgServers[idx].serverInfo.forwardType == AS {
				sel := CfgServers[idx].serverInfo.used
				CfgServers[idx].serverInfo.used = testASServer(fss, sel)
			} else if CfgServers[idx].serverInfo.forwardType == RR {
				for i := 0; i < len(fss); i++ {
					CfgServers[idx].multiServers[i].forwardServers[i].used = testRRServer(fss[i])
				}
			} else {
				return
			}
		} // multi loop
	} // forever
}
