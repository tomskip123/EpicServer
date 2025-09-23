package epicserver

import "net/http"

func (r *Renderer) FlashResponse(w http.ResponseWriter, message string) {
	data := map[string]any{
		"epicserver:flash": message,
	}

	HXReswap(w, "none")
	HXTrigger(w, data)

	w.Write([]byte{})
}
