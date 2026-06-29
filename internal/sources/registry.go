package sources

var registered []Source

func init() {
	registered = []Source{
		&ShodanSource{},
		&C99Source{},
		&CrtshSource{},
		&SecurityTrailsSource{},
		&SourcegraphSource{},
		&CloudSNISource{},
		&AbuseIPDBSource{},
	}
}

func All() []Source {
	return registered
}

func ByName(name string) Source {
	for _, s := range registered {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

func Names() []string {
	names := make([]string, len(registered))
	for i, s := range registered {
		names[i] = s.Name()
	}
	return names
}
