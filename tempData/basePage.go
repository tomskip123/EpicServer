package tempData

import (
	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
)

type PageHeading struct {
	Title   string
	Content string
}

type PageSeo struct {
	Title       string
	Description string
	Canonical   string
}

type PageBaseData struct {
	*structs.App
	User        *structs.UserMemoryCacheItem
	AssetEntry  string
	PageHeading PageHeading
	Data        gin.H
	PageSeo
	BackUrl string
}

func NewPageData(app *structs.App, user *structs.UserMemoryCacheItem, title, content, seoTitle, backUrl, canonical string) PageBaseData {
	return PageBaseData{
		App:        app,
		User:       user,
		AssetEntry: "index", // we couold have this as a static var
		PageHeading: PageHeading{
			Title:   title,
			Content: content,
		},
		PageSeo: PageSeo{
			Title:     seoTitle,
			Canonical: canonical,
		},
		Data:    gin.H{},
		BackUrl: backUrl,
	}
}
