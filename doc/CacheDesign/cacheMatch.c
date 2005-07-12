
/* Program to open a file (arg1) of Inode numbers (Grep from stat) and make a cache */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>


#define PRIMEBASE 30000   /* uses first prime less than this */
#define SETSIZE   2       /* semi-associative set size */

struct {
    dev_t         st_dev;      /* device */
    ino_t         st_ino;      /* inode */
} cache[PRIMEBASE];


#define MATCHSIZE 1000
int match[MATCHSIZE];     /* for simple matching tests */
int match_flag[MATCHSIZE];


/* check match list, return 1 if found and 0 otherwise */
int checkMatch(int value, int range) /* range is used for partial table match */
{
  while(range > 0) {
    if (value == match[--range]) return 1;
  }
  return 0;
}


/* find next prime lower than number given */
int findPrime(int inval)
{
  int i;
  int retval = inval;
  int max = sqrt(inval);

  while(max <= retval) {
    i = 2;
    while (i <= max) {
      if ((retval % i) == 0) {
	--retval;
	break;
      }
      ++i;
      if ((i & 1) == 0) ++i;
      if (i > max) {
	/* printf("Found prime %d\n", retval); */
	return retval;
      }
    }
  }

  printf("Failed to find prime lower than %d - exiting\n",inval);
  exit(1);
}

/* In final version, args are Filename, test entries, cache size, 0 or match 1 in n, set size, 2nd hash (p) */
int main(int argc, char* argv[])
{
  int i;
  FILE *f;
  struct timeval tStart, tEnd;
  time_t secs;
  suseconds_t usec;
  int count = 10000;
  char *linebuf = NULL;

  int c,j,s;
  int n = SETSIZE;
  int m = findPrime(PRIMEBASE);
  int p = (m + n - 2)/n;
  int r = 0;

  int scantotal = 0;
  int matches = 0;
  int replacements = 0;

  int random_flag = 0;
  int random_count = 0;
  int random_matches = 0;

  if (argc > 3) {
    m = atoi(argv[3]);
    if (m < 10) printf("arg3 too small %d\n",m);
    if (m == 0 || m > PRIMEBASE) m = PRIMEBASE;
    m = findPrime(m);
  }

  if (argc > 5) {
    n = atoi(argv[5]);
    if (n == 0) n = SETSIZE;
  }

  p = (m + n - 2)/n;

  if (argc > 6) {
    p = atoi(argv[6]);
    if (p >= m || p < 1 || (n > 2 && p >= m/(n-1))) {
      if (n > 2) p = m/(n-1);
      else p = m-1;
    }
  }

  p = findPrime(p);

  printf("Table size %d, 2nd hash prime %d, set size %d\n", m, p, n);

  if (m < 0 || 2*m < 0 || p < 4) {
    printf("Prime problem %d %d - exiting\n", m, p);
    return 1;
  }

  for (i = 0; i < PRIMEBASE; ++i) {
    cache[i].st_dev = -1;
    cache[i].st_ino = 0;
  }

  if (argc < 2) {
    printf("Need a file name\n");
    return 1;
  }

  f = fopen(argv[1], "r");
  if (f == NULL) {
    printf("Failed to open file\n");
    return 1;
  }

  if (argc > 2) {
    count = atoi(argv[2]);
    if (count == 0) count = 10000;
  }

  if (argc > 4) {
    random_flag = atoi(argv[4]);
    if (random_flag) {
      srandom(1);
      for (i = 0; i < MATCHSIZE; ++i) {
	match[i] = random() & 0xffff;
	while(checkMatch(match[i],i)) match[i] = random() & 0xffff;
	match_flag[i] = 0;
      }
    }
  }

  gettimeofday(&tStart, NULL);

  for (i = 0; i < count;) {
    size_t bufsize = 0;
    ssize_t got = getline(&linebuf, &bufsize, f);
    int dev2 = -1;
    int inode = 0;
    int index;

    if (got < 0) break;  /* probably end of file */

    if (got > 1) {
      sscanf(linebuf, "%d:%d", &dev2, &inode);

      if (dev2 == 775 && checkMatch(inode, MATCHSIZE)) continue; /* omit any that match is using */

      if (dev2 != -1 && inode != 0) {
	j = ((dev2%m)*(inode%m))%m;
	c = 0;
	s = ((dev2%p)*(inode%p))%p + 1;
	
	/* printf("Device %4d,  Inode %6d,  j %4d,  s %3d\n", dev2, inode, j, s); */

	++i;

	index = j;
	while (c < n) {
	  if (cache[index].st_dev == -1 && cache[index].st_ino == 0) {
	    /* empty - fill here */
	    cache[index].st_dev = dev2;
	    cache[index].st_ino = inode;
	    scantotal += c+1;
	    break;
	  }

	  if (cache[index].st_dev == dev2 && cache[index].st_ino == inode) {
	    /* match */
	    /* printf("Match Device %d Inode %d\n", dev2, inode); */
	    ++matches;
	    scantotal += c+1;
	    break;
	  }

	  /* skip to next index */
	  index = (index + s)%m;
	  ++c;
	}

	if (c >= n) {
	  /* here if (associative) set full */
	  index = (j + (r%n) * s)%m;
	  ++r;
	  cache[index].st_dev = dev2;
	  cache[index].st_ino = inode;
	  scantotal += n;
	  ++replacements;
	}
      }
    }
    /* If doing matches, trap 10% of cases (every 9th do one extra) */
    if (random_flag != 0 && ++random_count == random_flag) {
      int sel = random()%MATCHSIZE;   /* need to modify this to give distribution */
      random_count = 0;
      dev2 = 775;
      inode = match[sel];
      ++i;

      j = ((dev2%m)*(inode%m))%m;
      c = 0;
      s = ((dev2%p)*(inode%p))%p + 1;
	
      index = j;
      while (c < n) {
	if (cache[index].st_dev == -1 && cache[index].st_ino == 0) {
	  /* empty - fill here */
	  cache[index].st_dev = dev2;
	  cache[index].st_ino = inode;
	  scantotal += c+1;
	  ++match_flag[sel];    /* count number of times inserted */
	  break;
	}

	if (cache[index].st_dev == dev2 && cache[index].st_ino == inode) {
	  /* match */
	  /* printf("Match Device %d Inode %d\n", dev2, inode); */
	  ++matches;
	  scantotal += c+1;
	  ++random_matches;
	  break;
	}

	/* skip to next index */
	index = (index + s)%m;
	++c;
      }

      if (c >= n) {
	/* here if (associative) set full */
	index = (j + (r%n) * s)%m;
	++r;
	cache[index].st_dev = dev2;
	cache[index].st_ino = inode;
	scantotal += n;
	++replacements;
	++match_flag[sel];    /* count number of times inserted */
      }
    }
  }


  gettimeofday(&tEnd, NULL);

  free(linebuf);
  fclose(f);

  secs = tEnd.tv_sec - tStart.tv_sec;
  usec = tEnd.tv_usec - tStart.tv_usec;
  if (usec < 0) {
    usec += 1000000;
    --secs;
  }

  printf("%d entries added in %d.%06d secs\n", i, secs, usec);

  printf("%d scans, %d matches, %d replacements, %d%% final fill ratio\n",
	 scantotal, matches, replacements,
	 ((i - matches - replacements) * 100)/(m<(i-matches)?m:i-matches));

  if (random_flag) {
    int sum = 0;
    for (i = 0; i < MATCHSIZE; ++i) {
      if (match_flag[i] > 1) sum += match_flag[i] - 1;    /* number of EXTRA insertions == lost matches */
    }
    printf(" Match Stats: 1 in %d (%d%%), lost matches %d, good matches %d, ratio %d%%\n", random_flag+1,
	   100/(random_flag+1), sum, random_matches,
	   (random_matches * 100)/(random_matches+sum));
  }
  return 1;
}
