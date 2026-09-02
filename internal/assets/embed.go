package assets

import _ "embed"

//go:embed logo.png
var LogoPNG []byte

//go:embed wordlists/commands.txt
var CommandsWordlist string

//go:embed wordlists/api_paths.txt
var APIPathsWordlist string

//go:embed wordlists/start_payloads.txt
var StartPayloadsWordlist string

//go:embed wordlists/injection.txt
var InjectionWordlist string

//go:embed wordlists/callback_data.txt
var CallbackWordlist string
