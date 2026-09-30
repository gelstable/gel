.. _ref_guide_deployment_bare_metal:

==========
Bare Metal
==========

:edb-alt-title: Deploying Gel to a Bare Metal Server

In this guide we show how to deploy Gel to bare metal using your system's
package manager and systemd.

.. include:: ./note_cloud_reset_password.rst

Install the Gel Package
=======================

The steps for installing the Gel package will be slightly different
depending on your Linux distribution. Once you have the package installed you
can jump to :ref:`ref_guide_deployment_bare_metal_enable_unit`.


Debian/Ubuntu
-------------

Import the Gelstable packaging key and add the stable repository. Packages are
available for amd64 and arm64; the repository channel replaces the old distro
codename.

.. code-block:: bash

   $ sudo install -d -m 0755 /etc/apt/keyrings
   $ sudo curl -fsSLo /etc/apt/keyrings/gelstable.asc \
       https://registry.gelstable.com/keys/gelstable.asc
   $ echo 'deb [signed-by=/etc/apt/keyrings/gelstable.asc] https://registry.gelstable.com/apt stable main' \
       | sudo tee /etc/apt/sources.list.d/gelstable.list
   $ sudo apt-get update && sudo apt-get install gel-7

Remove any old Gel entries from your APT source configuration when migrating.
The epoch in the new packages makes them upgrade existing packages in place.

RHEL/Rocky Linux 9
-----------------

Import the Gelstable packaging key and add the stable repository. Packages are
available for x86_64 and aarch64. Before importing the downloaded key, compare
its full primary fingerprint with the production fingerprint published in the
`registry installation guide <https://github.com/gelstable/gel-registry/blob/main/docs/native-packages.md#verify-the-repository-key>`_.
Stop if they disagree.

.. code-block:: bash

   $ curl -fsSLo /tmp/gelstable.asc https://registry.gelstable.com/keys/gelstable.asc
   $ gpg --show-keys --with-fingerprint /tmp/gelstable.asc

After verifying the fingerprint, import the key and configure the repository:

.. code-block:: bash

   $ sudo rpm --import /tmp/gelstable.asc
   $ sudo tee /etc/yum.repos.d/gelstable.repo <<'EOF'
   [gelstable]
   name=Gelstable
   baseurl=https://registry.gelstable.com/rpm/stable/$basearch
   enabled=1
   gpgcheck=1
   repo_gpgcheck=1
   gpgkey=https://registry.gelstable.com/keys/gelstable.asc
   EOF
   $ sudo dnf install gel-7

Remove any old Gel repository files when migrating. For testing releases, use
``testing`` in place of ``stable`` in either repository configuration. See
`native package installation <https://github.com/gelstable/gel-registry/blob/main/docs/native-packages.md>`_
for key verification and migration details.


.. _ref_guide_deployment_bare_metal_enable_unit:

Enable a systemd unit
=====================

The Gel package comes bundled with a systemd unit that is disabled by
default. You can start the server by enabling the unit.

.. code-block:: bash

   $ sudo systemctl enable --now gel-server-7

This will start the server on port 5656, and the data directory will be
``/var/lib/gel/7/data``.

.. warning::

    |gel-server| cannot be run as root.

Set environment variables
=========================

To set environment variables when running Gel with ``systemctl``,

.. code-block:: bash

   $ systemctl edit --full gel-server-7

This opens a ``systemd`` unit file. Set the desired environment variables
under the ``[Service]`` section. View the supported environment variables at
:ref:`Reference > Environment Variables <ref_reference_environment>`.

.. code-block:: toml

   [Service]
   Environment="GEL_SERVER_TLS_CERT_MODE=generate_self_signed"
   Environment="GEL_SERVER_ADMIN_UI=enabled"

Save the file and exit, then restart the service.

.. code-block:: bash

   $ systemctl restart gel-server-7


Set a password
==============
There is no default password. To set one, you will first need to get the Unix
socket directory. You can find this by looking at your system.d unit file.

.. code-block:: bash

    $ sudo systemctl cat gel-server-7

Set a password by connecting from localhost.

.. code-block:: bash

   $ echo -n "> " && read -s PASSWORD
   $ RUNSTATE_DIR=$(systemctl show gel-server-7 -P ExecStart | \
      grep -o -m 1 -- "--runstate-dir=[^ ]\+" | \
      awk -F "=" '{print $2}')
   $ sudo gel --port 5656 --tls-security insecure --admin \
      --unix-path $RUNSTATE_DIR \
      query "ALTER ROLE admin SET password := '$PASSWORD'"

The server listens on localhost by default. Changing this looks like this.

.. code-block:: bash

   $ gel --port 5656 --tls-security insecure --password query \
      "CONFIGURE INSTANCE SET listen_addresses := {'0.0.0.0'};"

The listen port can be changed from the default ``5656`` if your deployment
scenario requires a different value.

.. code-block:: bash

   $ gel --port 5656 --tls-security insecure --password query \
      "CONFIGURE INSTANCE SET listen_port := 1234;"

You may need to restart the server after changing the listen port or addresses.

.. code-block:: bash

   $ sudo systemctl restart gel-server-7


Connecting your application
===========================

To connect your application to the Gel instance, you'll need to provide
connection parameters. Gel client libraries can be configured using either
a DSN (connection string) or individual environment variables.

Obtaining connection parameters
-------------------------------

Your connection requires the following components:

- **Host**: The IP address or hostname of your server (e.g., ``localhost``,
  ``192.168.1.100``, or ``gel.example.com``)
- **Port**: ``5656`` by default, or the custom port if you changed it with
  ``CONFIGURE INSTANCE SET listen_port``
- **Username**: |admin| (the default superuser)
- **Password**: The password you set with ``ALTER ROLE admin SET password``
- **Branch**: |main| (the default branch)

Construct the DSN using these values:

.. code-block:: bash

    $ GEL_DSN="gel://admin:<password>@<hostname>:5656"

Obtaining the TLS certificate
-----------------------------

If you configured Gel with ``GEL_SERVER_TLS_CERT_MODE=generate_self_signed``,
your application needs the certificate to connect securely.

The generated certificate is stored in the data directory. You can find it at:

.. code-block:: bash

    $ cat /var/lib/gel/7/data/edbtlscert.pem

Alternatively, retrieve it using the Gel CLI:

.. code-block:: bash

    $ gel --dsn $GEL_DSN --tls-security insecure \
        query "SELECT sys::get_tls_certificate()"

Using in your application
-------------------------

Set these environment variables where you deploy your application:

.. code-block:: bash

    GEL_DSN="gel://admin:<password>@<hostname>:5656"
    # For self-signed certificates, provide the CA cert:
    GEL_TLS_CA_FILE="/path/to/edbtlscert.pem"
    # Or embed the certificate content directly:
    GEL_TLS_CA="<certificate content>"

Gel's client libraries will automatically read these environment variables.

Local development with the CLI
------------------------------

To make your instance easier to work with during local development,
create an alias using :gelcmd:`instance link`.

.. note::

   The command groups :gelcmd:`instance` and :gelcmd:`project` are not
   intended to manage production instances.

.. code-block:: bash

    $ gel instance link \
        --dsn $GEL_DSN \
        --non-interactive \
        --trust-tls-cert \
        my_bare_metal_instance

You can now refer to the instance using the alias ``my_bare_metal_instance``.
Use this alias wherever an instance name is expected:

.. code-block:: bash

    $ gel -I my_bare_metal_instance
    Gel x.x
    Type \help for help, \quit to quit.
    gel>

Or apply migrations:

.. code-block:: bash

    $ gel -I my_bare_metal_instance migrate


Upgrading Gel
=============

When you want to upgrade to the newest point release upgrade the package and
restart the ``gel-server-7`` unit.


Debian/Ubuntu LTS
-----------------

.. code-block:: bash

   $ sudo apt-get update && sudo apt-get install --only-upgrade gel-7
   $ sudo systemctl restart gel-server-7


RHEL/Rocky Linux 9
-----------------

.. code-block:: bash

   $ sudo dnf upgrade gel-7
   $ sudo systemctl restart gel-server-7

Health Checks
=============

Using an HTTP client, you can perform health checks to monitor the status of
your Gel instance. Learn how to use them with our :ref:`health checks guide
<ref_guide_deployment_health_checks>`.
