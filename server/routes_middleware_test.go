package server

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"docklog/config"
	"docklog/db"
	"docklog/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

const authFailureDriverName = "docklog-auth-failure-test"

func init() {
	sql.Register(authFailureDriverName, authFailureDriver{})
}

type authFailureDriver struct{}

func (authFailureDriver) Open(name string) (driver.Conn, error) {
	var failAt int
	var passwordVersion int64 = 1
	if _, err := fmt.Sscanf(name, "%d,%d", &failAt, &passwordVersion); err != nil {
		return nil, err
	}
	return &authFailureConn{failAt: failAt, passwordVersion: passwordVersion}, nil
}

type authFailureConn struct {
	failAt          int
	passwordVersion int64
	queryCount      int
}

func (c *authFailureConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not supported")
}

func (*authFailureConn) Close() error { return nil }

func (*authFailureConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not supported")
}

func (c *authFailureConn) QueryContext(_ context.Context, _ string, _ []driver.NamedValue) (driver.Rows, error) {
	c.queryCount++
	if c.queryCount == c.failAt {
		return nil, errors.New("database is locked")
	}
	if c.queryCount == 1 {
		return &authFailureRows{
			columns: []string{
				"password_changed", "is_active", "password_version", "is_admin",
				"can_start", "can_stop", "can_restart", "can_delete", "can_shell",
				"is_restricted_access", "allowed_containers", "username",
			},
			values: []driver.Value{
				true, true, c.passwordVersion, true, false, false, false, false, false,
				false, ".*", "admin",
			},
		}, nil
	}
	return &authFailureRows{
		columns: []string{"password_changed"},
		values:  []driver.Value{true},
	}, nil
}

type authFailureRows struct {
	columns []string
	values  []driver.Value
	read    bool
}

func (r *authFailureRows) Columns() []string { return r.columns }

func (*authFailureRows) Close() error { return nil }

func (r *authFailureRows) Next(dest []driver.Value) error {
	if r.read {
		return io.EOF
	}
	r.read = true
	copy(dest, r.values)
	return nil
}

func TestPasswordChangeMiddlewareDatabaseFailuresReturn503(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprintf("query_%d", failAt), func(t *testing.T) {
			rec := invokePasswordChangeMiddleware(t, failAt, 1)

			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("expected 503, got %d body=%s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "database is locked") {
				t.Fatalf("database error leaked in response: %s", rec.Body.String())
			}
		})
	}
}

func TestPasswordChangeMiddlewareInvalidatedSessionStillReturns401(t *testing.T) {
	rec := invokePasswordChangeMiddleware(t, 0, 2)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "SESSION_INVALIDATED") {
		t.Fatalf("expected session invalidation code, got %s", rec.Body.String())
	}
}

func invokePasswordChangeMiddleware(t *testing.T, failAt int, passwordVersion int64) *httptest.ResponseRecorder {
	t.Helper()

	previousDB := db.DB
	previousAuthDisabled := config.AuthDisabled
	config.AuthDisabled = false
	t.Cleanup(func() {
		db.DB = previousDB
		config.AuthDisabled = previousAuthDisabled
	})

	testDB, err := sql.Open(authFailureDriverName, fmt.Sprintf("%d,%d", failAt, passwordVersion))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	testDB.SetMaxOpenConns(1)
	db.DB = testDB
	t.Cleanup(func() {
		_ = testDB.Close()
	})

	e := echo.New()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	ctx := e.NewContext(req, rec)
	ctx.Set("user", &jwt.Token{
		Claims: &models.UserClaims{ID: 1, PasswordVersion: 1},
		Valid:  true,
	})

	handler := (&Server{}).passwordChangeMiddleware()(func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})
	if err := handler(ctx); err != nil {
		t.Fatalf("middleware returned error: %v", err)
	}
	return rec
}
