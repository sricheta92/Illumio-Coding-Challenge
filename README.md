# Illumio-Coding-Challenge
This is repository contains solution of Illumio coding challenge.

#Testing
I used JUnit 5 for testing this functionality. I tested by covering corner cases of ports and IP address. 
The main thing that I wanted to test was making sure that the program still worked for the case when there was a range in the port and also the ipAddress. 

#Implmentation
For this assignment, I decided  to make run time efficient.I did it by creating a HashSet of NetworkRule object. I overrode the equals methods such that 2 network rules are similar when direction, protocol, port and IP address are same. 
This leads to O(1) run time. One thing we could do id to apply design patterns to it, Proxy pattern ould work in this scenario.

#Refinements
If time had permit, I would have added validations to all the input field. I would have declared enums for all defined protocols likd TCP, UDP.
I could have also used Navigarble tree to reduce the time complexity to O(logN).

