# Hunting the Known Unknown -- Software Supply Chain Attacks
Splunk .conf 2021 - SEC1745<br>
[Ryan Kovar (@meansec)](https://twitter.com/meansec) and [Marcus LaFerrera (@mlaferrera)](https://twitter.com/mlaferrera)


Welcome to the supplemental information from the above talk. You'll find all of the queries we used, along with any references to code, apps, and perhaps more.


## Queries

- Overview of JA3/s hashes:

        sourcetype="bro:ssl:json" ja3="*" ja3s="*" src_ip IN (192.168.70.0/24)
        | stats sparkline values(server_name) AS Domains, values(src_ip) as Clients, values(dest_ip) as Server count  by ja3, ja3s
        | sort count desc


- Identify first seen by `ja3`, `ja3s`, `src_ip`, and `server_name`:

        sourcetype="bro:ssl:json" ja3="*" ja3s="*" src_ip IN (192.168.70.0/24)
        | stats earliest(_time) as earliest latest(_time) as latest by ja3, ja3s, src_ip, server_name
        | eval maxlatest=now()  
        | eval isOutlier=if(earliest >= relative_time(maxlatest, "-1d@d"), 1, 0)
        | table ja3, ja3s, src_ip, server_name, earliest, latest, maxlatest, isOutlier
        | convert ctime(earliest) ctime(latest) ctime(maxlatest)
        | sort earliest desc


- Find rarest `ja3s` by `server_name`:

        sourcetype="bro:ssl:json" ja3="*" ja3s="*" src_ip IN (192.168.70.0/24)
        | stats earliest(_time) as earliest latest(_time) as latest by ja3, ja3s, src_ip, server_name
        | eval maxlatest=now()  
        | eval isOutlier=if(earliest >= relative_time(maxlatest, "-1d@d"), 1, 0)
        | table ja3, ja3s, src_ip, server_name, earliest, latest, maxlatest, isOutlier
        | convert ctime(earliest) ctime(latest) ctime(maxlatest)
        | sort earliest desc


- Discover abnormal `ja3s` with `anomalydetection`:

        sourcetype="bro:ssl:json" ja3="*" ja3s="*" src_ip IN (192.168.70.0/24)
        | anomalydetection method=histogram action=annotate pthresh=0.0001 src_ip, ja3, ja3s
        | stats sparkline max(log_event_prob) AS "Max Prob", min(log_event_prob) AS "Min Prob", values(probable_cause) AS "Probable Causes", values(dest_ip) AS "Dest IPs", values(server_name) AS "Server Names", values(ja3) AS "JA3", values(src_ip) as "Source IPs" count by ja3s
        | table "Server Names", "Probable Causes", "Max Prob", "Min Prob", "Dest IPs", ja3s, "JA3", "Source IPs", count
        | sort "Min Prob" asc


- Homemade anomaly detection with outputlookup:

        sourcetype="bro:ssl:json" ja3="*" ja3s="*" src_ip IN (192.168.70.0/24)
        | eval id=md5(src_ip+ja3+ja3s)
        | stats count by id,ja3,ja3s,src_ip
        | eventstats sum(count) as total_host_count by src_ip,ja3
        | eval hash_pair_likelihood=exact(count/total_host_count)
        | sort src_ip ja3 hash_pair_likelihood
        | streamstats sum(hash_pair_likelihood) as cumulative_likelihood by src_ip,ja3
        | eval log_cumulative_like=log(cumulative_likelihood)
        | eval log_hash_pair_like=log(hash_pair_likelihood)
        | outputlookup hash_count_by_host_baselines.csv


    - Then, using `inputlookup` to find anomalous activity:

            sourcetype="bro:ssl:json" ja3="*" ja3s="*" src_ip IN (192.168.70.0/24)
            | eval id=md5(src_ip+ja3+ja3s)
            | lookup hash_count_by_host_baselines.csv id as id OUTPUT count, total_host_count,log_cumulative_like, log_hash_pair_like
            | table _time, src_ip, ja3s, server_name, subject, issuer, dest_ip, ja3, log_cumulative_like, log_hash_pair_like, count, total_host_count
            | sort log_hash_pair_like


    - Periodically, the lookup table must be updated to ensure probabilities are accurate

            sourcetype="bro:ssl:json" ja3="*" ja3s="*" src_ip IN (192.168.70.0/24)
            | eval id=md5(src_ip+ja3+ja3s)
            | stats count by id,ja3,ja3s,src_ip
            | append 
                [| inputlookup hash_count_by_host_baselines.csv]
            | stats sum(count) as count by id,ja3,ja3s,src_ip
            | eventstats sum(count) as total_host_count by src_ip,ja3
            | eval hash_pair_likelihood=exact(count/total_host_count)
            | sort src_ip ja3 hash_pair_likelihood
            | streamstats sum(hash_pair_likelihood) as cumulative_likelihood by src_ip,ja3
            | eval log_cumulative_like=log(cumulative_likelihood)
            | eval log_hash_pair_like=log(hash_pair_likelihood)
            | outputlookup hash_count_by_host_baselines.csv


- Discover abnormal `ja3s` and `ASN` context with `anomalydetection`:

        sourcetype="bro:ssl:json" ja3="*" ja3s="*" src_ip IN (192.168.70.0/24)
        | lookup asparse prefix as dest_ip
        | anomalydetection method=histogram action=filter pthresh=0.0001 src_ip, ja3, ja3s, asn, org.name, geo.country
        | stats max(log_event_prob) AS "Max Prob", min(log_event_prob) AS "Min Prob", values(probable_cause) AS "Probable Causes", values(dest_ip) AS "Dest IPs", values(server_name) AS "Server Names", values(ja3) AS "JA3", values(src_ip) as "Source IPs", values(geo.country) AS "Countries" count by asn, org.name, ja3s
        | table asn, org.name, Countries, "Server Names", "Probable Causes", "Max Prob", "Min Prob", "Dest IPs", ja3s, "JA3", "Source IPs", count
        | sort "Min Prob" ASC


- Link JA3s hashes to Windows processes with sysmon:


        (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 src_ip IN (192.168.70.0/24))
            OR 
        (sourcetype="bro:ssl:json" ja3=* ja3s=*) 
        | eval src_ip=if(sourcetype == "bro:ssl:json",'id.orig_h','src_ip') 
        | eval src_port=if(sourcetype == "bro:ssl:json",'id.orig_p','src_port') 
        | eval dest_ip=if(sourcetype == "bro:ssl:json",'id.resp_h','dest_ip') 
        | eval dest_port=if(sourcetype == "bro:ssl:json",'id.resp_p','dest_port') 
        | stats values(ja3) as ja3 values(ja3s) as ja3s values(process_path) as process_path values(server_name) as server_name by src_ip dest_ip dest_port 
        | search ja3=* ja3s=* process_path=* NOT process_path IN ("&lt;unknown process&gt;")


- Same as above, but with datamodels:

        | multisearch 
            [ from datamodel:Network_Traffic.All_Traffic 
            | search sourcetype="xmlwineventlog" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" src_ip IN (192.168.70.0/24)
            | rename app as process_path] 
            [ search sourcetype="bro:ssl:json" ja3=* ja3s=*] 
        | eval src_ip=if(sourcetype == "bro:ssl:json",'id.orig_h','src_ip') 
        | eval src_port=if(sourcetype == "bro:ssl:json",'id.orig_p','src_port') 
        | eval dest_ip=if(sourcetype == "bro:ssl:json",'id.resp_h','dest_ip') 
        | eval dest_port=if(sourcetype == "bro:ssl:json",'id.resp_p','dest_port') 
        | stats count values(ja3) as ja3 values(ja3s) as ja3s values(process_path) as process_path, values(server_name) as server_name by src_ip dest_ip dest_port 
        | search ja3=* ja3s=* process_path=* NOT process_path IN ("&lt;unknown process&gt;")


## Tools


- [asparser](https://github.com/splunk/asparser)<br>
    - A python library that can quickly generate ASN and Geolocation datasets


- [aiohec](https://github.com/splunk/aiohec/)<br>
    - An async python library to quickly ingest data into a Splunk index via the HTTP Event Collector and inserting data into Splunk KVStore.


- [zeekgen](code/)<br>
    - A python script to generate synthentic Zeek TLS logs for attack simulation


## Splunk Apps


- [Machine Learning Toolkit](https://splunkbase.splunk.com/app/2890/)<br>
    - Splunk app that enables common machine learning techniques with minimal experience


- [Deep Learning Toolkit](https://splunkbase.splunk.com/app/4607/)<br>
    - Extension of MLTK for more advanced use cases
