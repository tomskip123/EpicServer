package structs

import (
	"fmt"
	"html/template"
	"time"
)

var TemplateFuncMap = template.FuncMap{
	"dict":     dict,
	"contains": contains,
	"yearNow":  yearNow,
}

func yearNow() string {
	year := time.Now().Year()
	return fmt.Sprintf("%d", year)
}

// dict function to create a map
func dict(values ...interface{}) (map[string]interface{}, error) {
	if len(values)%2 != 0 {
		return nil, fmt.Errorf("invalid dict call")
	}
	dict := make(map[string]interface{}, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict keys must be strings")
		}
		dict[key] = values[i+1]
	}
	return dict, nil
}

// contains checks if a slice contains a specific string
func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}
