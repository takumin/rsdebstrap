{
	include: [
		.tasks[] | select(
			.name | startswith("reviewdog:") and (
				(
					endswith("default") or endswith("matrix")
				) | not
			)
		) | {
			name: .name | split(":") | last,
			target: .name
		}
	]
}
