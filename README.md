# Par2Py

MIT Licensed par2 parser / A Python framework for interacting with Par2 files

Par2 is a file format for using Reed-Solomon Coding to perform file recovery operations using "blocks" of recovery data.



#Rationale
While working on a QR code based backup solution, I found myself wanting additional redundancy.
Which is where Par2 comes in.  Par2 is a great system with many advantages:

* Everything is in "packets", with extremely easy to decode headers.
* Packet headers are easy to find, with their "magic" values ?guaranteed? to only show up there.
* Any amount of padding (including random data) is allowed between packets.
* Provided that enough redundancy exists, a missing file can be completely reconstructed.

To increase the likelihood of file recovery I found myself needing to perform byte alignment on individual packets.
There were other reasons as well, but this led to creating a par2 parser, and I decided that it would be worth it as a standalone program.


# References:
* [Official Specification](http://parchive.sourceforge.net/docs/specifications/parity-volume-spec/article-spec.html)
* [Packet & Header format](https://github.com/Parchive/par2cmdline/blob/master/src/par2fileformat.h)
* ["magic" & "type"/"signature" values](https://github.com/Parchive/par2cmdline/blob/master/src/par2fileformat.cpp)

Note that you can recover everything in the second link easily from any "vol...par2" file.

# Other (similar) projects:
* [par2ools](https://github.com/jmoiron/par2ools) by Jason Moiron
