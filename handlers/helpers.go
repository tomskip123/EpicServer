package handlers

import (
	"net/http"

	"github.com/cyberthy/server/tempData"
	"github.com/gin-gonic/gin"
)

func RenderPage(ctx *gin.Context, isHtmx bool, fullPageTemplate string, partialTemplate string, pageData tempData.PageBaseData) {
	if !isHtmx {
		// respond with a template
		ctx.HTML(http.StatusOK, fullPageTemplate, pageData)
	} else {
		ctx.HTML(http.StatusOK, partialTemplate, pageData)
	}
}

func HtmxTrigger(ctx *gin.Context, event string) {
	ctx.Header("HX-Trigger", event)
}
