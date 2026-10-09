package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"shiguang-relay/internal/httpapi"
)

func TestHealthzReportsDependencyState(t *testing.T) {
	// 依赖全绿 → 200
	deps := httpapi.Deps{
		HealthPG:    func(context.Context) error { return nil },
		HealthRedis: func(context.Context) error { return nil },
	}
	srv := httptest.NewServer(httpapi.NewRouter(deps))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/v1/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("依赖正常期望 200，实际 %d", resp.StatusCode)
	}
	var out struct {
		OK     bool              `json:"ok"`
		Checks map[string]string `json:"checks"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if !out.OK || out.Checks["pg"] != "up" || out.Checks["redis"] != "up" {
		t.Fatalf("探针状态异常: %+v", out)
	}

	// PG 不可达 → 503（部署探针据此摘流量）
	badDeps := httpapi.Deps{
		HealthPG:    func(context.Context) error { return errors.New("pg down") },
		HealthRedis: func(context.Context) error { return nil },
	}
	badSrv := httptest.NewServer(httpapi.NewRouter(badDeps))
	defer badSrv.Close()
	resp2, err := badSrv.Client().Get(badSrv.URL + "/v1/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("PG 不可达期望 503，实际 %d", resp2.StatusCode)
	}
}
