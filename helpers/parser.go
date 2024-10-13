package helpers

import (
	"github.com/gin-gonic/gin"
)

func IsRequestFromHTMX(ctx *gin.Context) bool {
	return len(ctx.GetHeader("HX-Request")) > 0
}

// ParseSuggestionsIntoHtml parses suggestions from the given note.

// hasContent checks if a node has meaningful content
