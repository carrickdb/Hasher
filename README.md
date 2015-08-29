Gathers hashes of data in a Dropbox or Google Drive account. A modification of FSL Tracer (http://tracer.filesystems.org/).

This program was developed for a study at the University of Connecticut on data deduplication rates in cloud storage accounts within peer groups. It is a streamlined version of FSL Tracer for easier and more automated use by participants in the study.

Participants in the study are able to download the program from http://sigma.engr.uconn.edu/peergroup/index.php, which I also created.

The bulk of the modifications are in fs-tracer.c, from line 1397 to the end.

You should be able to build the project on any *nix machine via ./configure, make, make install. Run with "fs-hasher" command.