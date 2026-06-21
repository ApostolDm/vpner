package buildinfo

var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

func String() string {
	s := Version
	if Commit != "" {
		s += " (" + Commit + ")"
	}
	if Date != "" {
		s += " " + Date
	}
	return s
}
