\set ON_ERROR_STOP on

-- The tenant networks are isolated libvirt NAT networks in the optional lab.
ALTER SYSTEM SET listen_addresses = '*';
