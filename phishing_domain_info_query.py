# -*- coding: UTF-8 -*-
import DNS
import urllib
import socket
import MySQLdb
socket.setdefaulttimeout(5)


def domain_online_query(query, type):
    if type == "A":
        return dict_build(query, type)
    elif type == "NS":
        return dict_build(query, type)
    elif type == "CNAME":
        return dict_build(query, type)
    elif type == "SOA":
        return dict_build(query, type)
    elif type == "PTR":
        return dict_build(query, type)
    elif type == "MX":
        return dict_build(query, type)
    elif type == "TXT":
        return dict_build(query, type)
    elif type == "STATUS":
        return domain_online_judge(query)
    elif type == "ANY":
        return any_dict_combine(query)


def dict_build(query, type):
    dict_domain = {}
    dict_domain['query_domain'] = query
    dict_domain['query_type'] = type
    dict_domain['query_answer'] = record_combine(query, type)
    return dict_domain


def any_dict_combine(query):
    dict_domain = {}
    dict_domain['query_domain'] = query
    dict_domain['query_type'] = "all"
    dict_domain['A_record'] = record_combine(query, "A")
    dict_domain['NS_record'] = record_combine(query, "NS")
    dict_domain['CNAME_record'] = record_combine(query, "CNAME")
    dict_domain['SOA_record'] = record_combine(query, "SOA")
    dict_domain['PTR_record'] = record_combine(query, "PTR")
    dict_domain['MX_record'] = record_combine(query, "MX")
    dict_domain['TXT_record'] = record_combine(query, "TXT")
    dict_domain_total = dict_domain.copy()
    dict_domain_total.update(domain_online_judge(query))
    return dict_domain_total


def record_combine(query, type):
    dict_a_record = {}
    try:
        if type == "A":
            type_query = DNS.Type.A
        elif type == "NS":
            type_query = DNS.Type.NS
        elif type == "CNAME":
            type_query = DNS.Type.CNAME
        elif type == "SOA":
            type_query = DNS.Type.SOA
        elif type == "PTR":
            type_query = DNS.Type.PTR
        elif type == "MX":
            type_query = DNS.Type.MX
        elif type == "TXT":
            type_query = DNS.Type.TXT
        DNS.DiscoverNameServers()
        reqobj = DNS.Request()
        answerobj_a = reqobj.req(
            name=query, qtype=type_query, server="223.5.5.5")
        if not len(answerobj_a.answers):
            dict_a_record = {type: 'not found'}
        else:
            for item in answerobj_a.answers:
                if item['typename'] == "SOA":
                    dict_a_record[item['typename']] = soa_tuple_operate(item['data'])
                else:
                    try:
                        if dict_a_record[item['typename']]:
                            dict_a_record[item['typename']] = dict_a_record[item['typename']] + " " + item['data']
                    except:
                        dict_a_record[item['typename']] = item['data']
    except:
        dict_a_record = {type: 'timeout'}
    return dict_a_record


def soa_tuple_operate(tuple_soa):
    soa_dict = {}
    soa_dict['name_server'] = tuple_soa[0]
    soa_dict['responsible_person'] = tuple_soa[1]
    soa_dict['serial'] = tuple_soa[2][1]
    soa_dict['refresh'] = {'second':tuple_soa[3][1],'time':tuple_soa[3][2]}
    soa_dict['retry'] = {'second':tuple_soa[4][1],'time':tuple_soa[4][2]}
    soa_dict['expire'] = {'second':tuple_soa[5][1],'time':tuple_soa[5][2]}
    soa_dict['minimum'] = {'second':tuple_soa[6][1],'time':tuple_soa[6][2]}
    return soa_dict


def record_judge(query):
    try:
        DNS.DiscoverNameServers()
        reqobj = DNS.Request()
        answerobj_a = reqobj.req(
            name=query, qtype=DNS.Type.A, server="223.5.5.5")
        if len(answerobj_a.answers):
            return 1
        else:
            pass
    except:
        pass
    try:
        DNS.DiscoverNameServers()
        reqobj = DNS.Request()
        answerobj_a = reqobj.req(
            name=query, qtype=DNS.Type.MX, server="223.5.5.5")
        if len(answerobj_a.answers):
            return 1
        else:
            pass
    except:
        pass
    return 0


def http_code(query):
    '''
    查询http状态码
    '''
    try:
        status = urllib.urlopen(query)
        return str(status.getcode())
    except:
        return "error"


def domain_online_judge(query):
    domain = "http://" + query + "/"
    if(record_judge(query) == 1 and (http_code(domain)[0] == "2" or http_code(domain)[0] == "3")):
        dict_domain = {}
        dict_domain['query_domain'] = query
        dict_domain['status'] = "online"
        dict_domain['http_code'] = http_code(domain)
        return dict_domain
    else:
        dict_domain = {}
        dict_domain['query_domain'] = query
        dict_domain['status'] = "not online"
        dict_domain['http_code'] = http_code(domain)
        return dict_domain


def phishing_domain_info_insert():
    db = MySQLdb.connect(
        "172.29.152.249 ", "root", "platform", "malicious_domain_collection")
    cursor = db.cursor()
    sql = "select domain from malicious_domain_collection_complete where flag_judge is null and flag_info is null"
    cursor.execute(sql)
    results = cursor.fetchall()
    flag_commit = 0
    for row in results:
        domain = row[0]
        try:
            a_record = domain_online_query(domain, "A")['query_answer']['A']
        except:
            a_record = "not found"
        try:
            ns_record = domain_online_query(domain, "NS")['query_answer']['NS']
        except:
            ns_record = "not found"
        try:
            cname_record = domain_online_query(domain, "CNAME")['query_answer']['CNAME']
        except:
            cname_record = "not found"
        sql = "update malicious_domain_collection_complete set a_record = " + "'" + str(a_record) + "'" + ",ns_record = " + "'" + str(ns_record) + "'" +",cname_record = " + "'" + str(cname_record) + "'" +",flag_info = 1 where domain = " + "'" + domain + "'"
        cursor.execute(sql)
        flag_commit = flag_commit + 1
        if flag_commit == 10:
            print 10
            db.commit()
            flag_commit = 0
    db.commit()
    db.close()


if __name__ == "__main__":
    # a = domain_online_query("zyxghsbdpk4a.info","CNAME")
    # print a['query_answer']['CNAME']
    phishing_domain_info_insert()




