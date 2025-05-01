{
	source: {
		name: "shellcheck",
		url: "https://github.com/koalaman/shellcheck"
	},
	diagnostics: . | map({
		message: .message,
		code: {
			value: "SC\(.code)",
			url: "https://github.com/koalaman/shellcheck/wiki/SC\(.code)",
		},
		location: {
			path: .file,
			range: {
				start: {
					line: .line,
					column: .column
				},
				end: {
					line: .endLine,
					column: .endColumn
				}
			}
		},
		severity: ((.level|ascii_upcase|select(match("ERROR|WARNING|INFO")))//null)
	})
}
