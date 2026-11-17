package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Exploración del panel del router: inicia sesión, recorre las páginas del
// menú y guarda la respuesta de cada endpoint de lectura que encuentra.
// Solo hace peticiones GET, que en este firmware nunca cambian la configuración.

var (
	reEndpoint = regexp.MustCompile(`_type=(menuView|menuData|hiddenData|vueData)&(?:amp;)?_tag=([A-Za-z0-9_.]+)`)
	// Etiquetas que no se visitan ni por GET: acciones o cambios de sesión.
	skipTags = []string{"logout", "login", "reboot", "restart", "reset", "restore", "default",
		"upgrade", "update", "modeswitch", "switchlang", "backup", "download", "upload", "diag"}
)

var (
	reMenuTree = regexp.MustCompile(`var menuTreeJSON = \[.*`)
	reMenuID   = regexp.MustCompile(`"id":"([A-Za-z0-9_]+)"`)
)

const maxExploreRequests = 500

type exploredEndpoint struct {
	Query     string
	Bytes     int
	Instances int
	Params    []string
	Error     string
}

func skipTag(tag string) bool {
	lower := strings.ToLower(tag)
	for _, word := range skipTags {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

func (z *zteClient) explore(dir string) ([]exploredEndpoint, error) {
	if err := z.login(); err != nil {
		return nil, err
	}
	defer z.logout()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	queue := []string{""} // la página principal ya con sesión
	queued := map[string]bool{"": true}
	enqueue := func(body []byte) {
		var found []string
		add := func(kind, tag string) {
			if skipTag(tag) {
				return
			}
			query := "?_type=" + kind + "&_tag=" + tag
			if kind == "menuView" {
				query += "&Menu3Location=0"
			}
			if !queued[query] {
				queued[query] = true
				found = append(found, query)
			}
		}
		for _, match := range reEndpoint.FindAllStringSubmatch(string(body), -1) {
			add(match[1], match[2])
		}
		// Los datos de una página se piden justo después de visitarla: el
		// router los rechaza (SessionTimeout) si la última página vista es otra.
		queue = append(found, queue...)

		// El árbol de menús viene como JSON dentro de la página principal
		found = nil
		if tree := reMenuTree.Find(body); tree != nil {
			for _, match := range reMenuID.FindAllSubmatch(tree, -1) {
				add("menuView", string(match[1]))
			}
		}
		queue = append(queue, found...)
	}

	var results []exploredEndpoint
	for len(queue) > 0 && len(results) < maxExploreRequests {
		query := queue[0]
		queue = queue[1:]
		entry := exploredEndpoint{Query: query}
		body, err := z.request("GET", query, nil)
		if err != nil {
			entry.Error = err.Error()
			results = append(results, entry)
			continue
		}
		entry.Bytes = len(body)
		instances, errStr := z.parseInstances(body)
		entry.Instances = len(instances)
		if errStr != "" && errStr != "SUCC" {
			entry.Error = errStr
		}
		names := map[string]bool{}
		for _, values := range instances {
			for name := range values {
				names[name] = true
			}
		}
		for name := range names {
			entry.Params = append(entry.Params, name)
		}
		sort.Strings(entry.Params)

		name := "index.html"
		if query != "" {
			name = strings.NewReplacer("?_type=", "", "&_tag=", "__", "&Menu3Location=0", "").Replace(query) + ".txt"
		}
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			return results, err
		}
		results = append(results, entry)
		enqueue(body)
		time.Sleep(150 * time.Millisecond) // sin prisa: es un router doméstico
	}
	return results, nil
}

// routerExplore guarda el volcado y un índice legible sin datos sensibles
// (solo nombres de endpoints y de parámetros, no sus valores).
func routerExplore() error {
	client, err := routerClient()
	if err != nil {
		return err
	}
	dir := resolvePath("data/router-dump")
	results, err := client.explore(dir)
	if err != nil && len(results) == 0 {
		return err
	}

	var index strings.Builder
	withData := 0
	for _, r := range results {
		query := r.Query
		if query == "" {
			query = "(página principal)"
		}
		fmt.Fprintf(&index, "%-70s %7d B  %3d inst", query, r.Bytes, r.Instances)
		if r.Error != "" {
			fmt.Fprintf(&index, "  [%s]", r.Error)
		}
		index.WriteString("\n")
		if len(r.Params) > 0 {
			withData++
			fmt.Fprintf(&index, "    %s\n", strings.Join(r.Params, ", "))
		}
	}
	indexPath := filepath.Join(dir, "INDEX.txt")
	if writeErr := os.WriteFile(indexPath, []byte(index.String()), 0o600); writeErr != nil {
		return writeErr
	}
	fmt.Print(index.String())
	fmt.Printf("\n%d endpoints visitados, %d con datos.\nÍndice: %s\n", len(results), withData, indexPath)
	fmt.Printf("AVISO: los archivos de %s contienen datos de tu router (claves WiFi incluidas). No los compartas.\n", dir)
	return err
}
