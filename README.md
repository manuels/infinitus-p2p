infinitus-p2p
=============

A peer-to-peer service


Currently this is just a bunch of code with test files.
Run `make tests` to watch it in action.

The design looks like this:
- a service can watch for changes of the local IP address via DBUS and tell it to other peers (e.g. using IRC)
- local programs can establish a connection socket to any remote peers using DBUS
