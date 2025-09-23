package epiccli

import "github.com/tomskip123/EpicServer/config"

func CmdValidate(path string) error {
	_, err := config.Load(path)
	return err
}
