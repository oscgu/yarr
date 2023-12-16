package auth

import (
	"net/http"
	"strings"

	"github.com/nkanaev/yarr/src/assets"
	"github.com/nkanaev/yarr/src/server/router"
	"github.com/pquerna/otp/totp"
)

type Middleware struct {
	Username  string
	Password  string
	OtpSecret string
	BasePath  string
	Public    []string
}

func (m *Middleware) Handler(c *router.Context) {
	for _, path := range m.Public {
		if strings.HasPrefix(c.Req.URL.Path, m.BasePath+path) {
			c.Next()
			return
		}
	}
	if IsAuthenticated(c.Req, m.Username, m.Password) {
		c.Next()
		return
	}

	rootUrl := m.BasePath + "/"

	if c.Req.URL.Path != rootUrl {
		c.Out.WriteHeader(http.StatusUnauthorized)
		return
	}

	if c.Req.Method == "POST" {
		username := c.Req.FormValue("username")
		password := c.Req.FormValue("password")
		passcode := c.Req.FormValue("passcode")
		if StringsEqual(username, m.Username) && StringsEqual(password, m.Password) && (totp.Validate(passcode, m.OtpSecret) || m.OtpSecret == "") {
			Authenticate(c.Out, m.Username, m.Password, m.BasePath)
			c.Redirect(rootUrl)
			return
		} else {
			c.HTML(http.StatusOK, assets.Template("login.html"), map[string]string{
				"username": username,
				"error":    "Invalid username/password/otp",
			})
			return
		}
	}
	c.HTML(http.StatusOK, assets.Template("login.html"), nil)
}
