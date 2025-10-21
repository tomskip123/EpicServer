package render

import (
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
)

func (r *Renderer) loadShared() error {
	root := template.New("root").Funcs(r.Funcs)
	var files []string
	for _, dir := range []string{r.LayoutsDir, r.ComponentsDir} {
		base := filepath.Join(r.BaseDir, dir)
		_ = filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // skip errors during walk; handled on parse
			}
			if d.IsDir() {
				return nil
			}
			if filepath.Ext(path) != r.Ext {
				return nil
			}
			files = append(files, path)
			return nil
		})
	}
	if len(files) == 0 {
		r.mu.Lock()
		r.shared = root
		r.pageCache = map[string]*template.Template{}
		r.mu.Unlock()
		return nil
	}
	t, err := root.ParseFiles(files...)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.shared = t
	r.pageCache = map[string]*template.Template{}
	r.mu.Unlock()
	return nil
}

func (r *Renderer) cloneWithPage(page string) (*template.Template, error) {
	pageKey := filepath.ToSlash(page)
	r.mu.RLock()
	if !r.Dev {
		if t, ok := r.pageCache[pageKey]; ok {
			r.mu.RUnlock()
			return t, nil
		}
	}
	shared := r.shared
	r.mu.RUnlock()
	if shared == nil || r.Dev {
		if err := r.loadShared(); err != nil {
			return nil, err
		}
		r.mu.RLock()
		shared = r.shared
		r.mu.RUnlock()
	}
	clone, err := shared.Clone()
	if err != nil {
		return nil, err
	}
	pagePath := r.resolvePagePath(page)
	if _, err := os.Stat(pagePath); err != nil {
		return nil, err
	}
	if _, err := clone.ParseFiles(pagePath); err != nil {
		return nil, err
	}
	if !r.Dev {
		r.mu.Lock()
		r.pageCache[pageKey] = clone
		r.mu.Unlock()
	}
	return clone, nil
}

func (r *Renderer) cloneWithLazy(name string) (*template.Template, error) {
	r.mu.RLock()
	shared := r.shared
	r.mu.RUnlock()
	if shared == nil || r.Dev {
		if err := r.loadShared(); err != nil {
			return nil, err
		}
		r.mu.RLock()
		shared = r.shared
		r.mu.RUnlock()
	}
	clone, err := shared.Clone()
	if err != nil {
		return nil, err
	}
	path := r.resolveLazyPath(name)
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	if _, err := clone.ParseFiles(path); err != nil {
		return nil, err
	}
	return clone, nil
}
