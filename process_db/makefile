cc = gcc
cflag = -I /usr/include/mysql -L /usr/local/lib
source_req = pro_req.c
source_res = pro_res.c

goal_req = req
goal_res = res

req:$(source)
	$(cc) $(source_req) -o $(goal_req) $(cflag) -lmysqlclient -lpcap
	./$(goal_req)
	rm $(goal_req)

res:$(source)
	$(cc) $(source_res) -o $(goal_res) $(cflag) -lmysqlclient -lpcap
	./$(goal_res)
	rm $(goal_res)
	
clean:
	rm $(goal_req) $(goal_res)
