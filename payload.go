package gin_paseto_session

import (
	"context"
)

func (m Middleware) ExtractPayload(c context.Context) interface{} {
	iface := c.Value(PayloadKey)

	return iface
}
