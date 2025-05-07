{
	include: [
		.[] as $t | ["debug", "release"][] | {profile: ., target: $t}
	]
}
