#include <stdlib.h>
#include <stdio.h>

char *GetType (int size)
{
	if (size == sizeof (char)) return "char";
	if (size == sizeof (short)) return "short";
	if (size == sizeof (int)) return "int";
	if (size == sizeof (long)) return "long";
	if (size == sizeof (long long)) return "long long";

	fprintf (stderr, "Error: No type available for %d bytes\n", size);
	exit (1);
}

int main(int argc, char **argv)
{
	printf ("TYPES := -D__int8=\"%s\" -D__int16=\"%s\" -D__int32=\"%s\" -D__int64=\"%s\"\n",
		GetType (1), GetType (2), GetType (4), GetType (8));

	exit (0);
}
