from Firewall import FireWall
from time import time

print("Testing Firewall")

path_to_rules = 'test.csv'
start_read_time = time()
my_firewall = FireWall(path_to_rules)
end_read_time = time()

print("Total Time to parse Rules: {0} seconds".format(end_read_time-start_read_time))


print("Finished reading in Rules, beginning test cases")
## check that certain connections allowed through##
print("Test1")
test1 = ["inbound","tcp",80,"192.168.1.2"]
if my_firewall.accept_packet(*test1):
    print("Passed Test1")
else:
    print("Failed Test1")


print("Test2")
test2 = ["outbound","udp",2000,"52.12.48.92"]
if my_firewall.accept_packet(*test1):
    print("Passed Test2")
else:
    print("Failed Test2")


print("Test3")
test3 = ["inbound","udp",53,"192.168.1.200"]
if my_firewall.accept_packet(*test1):
    print("Passed Test3")
else:
    print("Failed Test3")
## check that certain connections are blocked##
print("Test4")
test3 = ["outbound","tcp",2000,"52.25.1.200"]
if my_firewall.accept_packet(*test1):
    print("Failed Test4")
else:
    print("Passed Test4")