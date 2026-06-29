package banner

import "fmt"

const art = `
   _____         __     __                   __
  / ___/ __  __ / /_   / /_   __  __ ____   / /_ ___   _____
  \__ \ / / / // __ \ / __ \ / / / // __ \ / __// _ \ / ___/
 ___/ // /_/ // /_/ // / / // /_/ // / / // /_ /  __// /
/____/ \__,_//_.___//_/ /_/ \__,_//_/ /_/ \__/ \___//_/

`

// Print prints the ASCII art banner to stdout.
func Print() {
	fmt.Println(art)
}
