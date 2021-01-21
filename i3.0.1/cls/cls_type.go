package cls

type RESULT int

const (
	CONF_ERR RESULT = -1
	CONF_NET        = -2
	CONF_OK         = iota
)

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