"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        host1 = self.addHost( 'h1' )
        host2 = self.addHost( 'h2' )
        host3 = self.addHost( 'h3' )
        host4 = self.addHost( 'h4' )
        switch1 = self.addSwitch( 's12' )
        switch2 = self.addSwitch( 's11' )
        switch3 = self.addSwitch( 's22' )
        switch4 = self.addSwitch( 's34' )

        # Add links
        self.addLink( host1, switch1 )
        self.addLink( host2, switch1 )
        self.addLink( host3, switch4 )
        self.addLink( host4, switch4 )
        self.addLink( switch1, switch2 )
        self.addLink( switch1, switch3 )
        self.addLink( switch4, switch2 )
        self.addLink( switch4, switch3 )

class MyTopo2( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        host1 = self.addHost( 'h1' )
        host2 = self.addHost( 'h2' )
        host3 = self.addHost( 'h3' )
        host4 = self.addHost( 'h4' )
        host5 = self.addHost( 'h5' )
        switch1 = self.addSwitch( 's12' )
        switch2 = self.addSwitch( 's11' )
        switch3 = self.addSwitch( 's22' )
        switch4 = self.addSwitch( 's34' )
        switch5 = self.addSwitch( 's33' )
        switch6 = self.addSwitch( 's44' )
        switch7 = self.addSwitch( 's55' )

        # Add links
        self.addLink( host1, switch1 )
        self.addLink( host2, switch1 )
        self.addLink( host3, switch4 )
        self.addLink( host4, switch4 )
        self.addLink( host5, switch7 )
        self.addLink( switch1, switch2 )
        self.addLink( switch1, switch3 )
        self.addLink( switch4, switch2 )
        self.addLink( switch4, switch3 )
        self.addLink( switch5, switch2 )
        self.addLink( switch5, switch3 )
        self.addLink( switch5, switch6 )
        self.addLink( switch6, switch7 )



topos = { 'mytopo': ( lambda: MyTopo() ) }
topos = { 'mytopo2': ( lambda: MyTopo2() ) }
