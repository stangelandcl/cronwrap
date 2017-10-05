cronwrap:	
	$(CC) -O -o cronwrap cronwrap.c

debug:
	$(CC) -O -DDEBUG=1 -o cronwrap cronwrap.c

clean:
	rm -f *.o cronwrap

lint:
	lint -u -x cronwrap.c > lint.out 2>&1
	
