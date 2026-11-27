#line 1616 "src/parser.c"
sbat_entry_t* GetSbatEntries(char* sbatlevel)
{
	BOOL eol, eof;
	char* version_str;
	uint32_t i, num_entries;
	sbat_entry_t* sbat_list;

	if (sbatlevel == NULL)
		return NULL;

	num_entries = 1;
	for (i = 0; sbatlevel[i] != '\0'; i++) {
		if (sbatlevel[i] == '\n')
			num_entries++;
		if (sbatlevel[i] == '\r')
			sbatlevel[i] = '\n';
	}

	sbat_list = calloc(num_entries + 1, sizeof(sbat_entry_t));
	if (sbat_list == NULL)
		return NULL;

	num_entries = 0;
	for (i = 0; sbatlevel[i] != '\0'; ) {
		// Eliminate blank lines
		if (sbatlevel[i] == '\n') {
			i++;
			continue;
		}
		// Eliminate comments
		if (sbatlevel[i] == '#') {
			while (sbatlevel[i] != '\n' && sbatlevel[i] != '\0')
				i++;
			continue;
		}
		sbat_list[num_entries].product = &sbatlevel[i];
		for (; sbatlevel[i] != ',' && sbatlevel[i] != '\0' && sbatlevel[i] != '\n'; i++);
		if (sbatlevel[i] == '\0' || sbatlevel[i] == '\n')
			break;
		sbatlevel[i++] = '\0';
		version_str = &sbatlevel[i];
		for (; sbatlevel[i] != ',' && sbatlevel[i] != '\0' && sbatlevel[i] != '\n'; i++);
		eol = (sbatlevel[i] == '\0' || sbatlevel[i] == '\n');
		eof = (sbatlevel[i] == '\0');
		sbatlevel[i] = '\0';
		if (!eof)
			i++;
		// Allow the provision of an hex version
		if (version_str[0] == '0' && version_str[1] == 'x')
			sbat_list[num_entries].version = strtoul(version_str, NULL, 16);
		else
			sbat_list[num_entries].version = strtoul(version_str, NULL, 10);
		if (!eol)
			for (; sbatlevel[i] != '\0' && sbatlevel[i] != '\n'; i++);
		if (sbat_list[num_entries].version != 0)
			num_entries++;
	}
	if (num_entries == 0) {
		free(sbat_list);
		return NULL;
	}

	return sbat_list;
}
