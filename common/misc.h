struct	systab	{
	const char	*name;
	int		value;
};

extern struct systab errnos[100 + 1];
extern struct systab signals[64 + 1];

#define	MAXERRNOS	100
#define	MAXSIGNALS	64
