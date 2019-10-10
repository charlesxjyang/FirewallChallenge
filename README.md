# FirewallChallenge

## What I did

I implemented a rule-based firewall using a python class called FireWall. I used Pandas dataframe as my datastructure and used some numpy arrays as well.
I used a pandas dataframe to encode the protocol and direction as hierarchical columns and the rows as the port number. Each entry in the dataframe
corresponded to a list of instances of the class IPrange, which was able to take in IP addresses as ranges or single values and store them in constant space.


I also created several test cases


## What I would do differently if I had more time

I used Python because its the language I'm most familiar with for parsing csv files in and because
given the limited time frame, its the fastest scripting language to iterate and design in. However, with more time,
I would definitely work in a lower level language such as Java or C to improve both memory and runtime.

Concretely, I would instead use bitstring representations of the IPv4 and port ranges. 
Thus, all rules can be encoded as a bit string. Because bit strings are the most native data representation for computers,
it would be much faster to check if a given input fits the allowed policies.


## What I would like to do at Illumio

I would be most interested in working on the Data team, in particular, 
Data Visualization and Analysis. Personally, I'm interested in how we manage data,
how we can analyze data to extract useful rules and policies, as well as
how to understand data in a human-first format i.e. visualizations.