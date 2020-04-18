@load base/frameworks/sumstats


event zeek_init()
    {

    local r1 = SumStats::Reducer($stream="num of reply", $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="num of all 404", 
                                 $apply=set(SumStats::SUM));
    local r3 = SumStats::Reducer($stream="num of unique 404",$apply=set(SumStats::UNIQUE));
    SumStats::create([$name="dns.requests.unique",
                      $epoch=10mins,
                      $reducers=set(r1,r2,r3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local numOfReply = result["num of reply"];
	        local numOf404= result["num of all 404"];
	        local numOfU404= result["num of unique 404"];
		if(numOf404$num>2 && numOf404$num/numOfReply$num>0.2 && numOfU404$unique/numOf404$num>0.5 ）
                        print fmt("%s is a scanner with %d scan attempts on  %d urls", 
                        			key$host, numOf404$num, numOfU404$unique);
                        }]);
    }


event http_reply(c:connection,version:string,code: count, reson:string)
{
                local st1 = c$http$host;

    	local st2 = c$http$uri;

    	local st3 = st1 + st2;

    SumStats::observe("num of reply", SumStats::Key[$host=c$id$orig_h], SumStats::Observation($num=1));
	if(code==404)
{
    SumStats::observe("num of all 404", SumStats::Key[$host=c$id$orig_h], SumStats::Observation($num=1));
    SumStats::observe("num of unique 404", SumStats::Key[$host=c$id$orig_h], SumStats::Observation($str=st3));		
    
}
}
