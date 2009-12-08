/*******************************************************************************\
 * RuijieClient -- a CLI based Ruijie Client authentication modified from mystar *
 *                                                                               *
 * Copyright (C) Gong Han, Chen Tingjun  microcai  sthots                                      *
 \*******************************************************************************/

/*
 * This program is modified from MyStar, the original author is netxray@byhh.
 *
 * AUTHORS:
 *   Alex Yang  <sthots AT gmail.com> from HIT at Weihai
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */
 
using GLib;

private static class RuijieDbus : GLib.Object {

    private DBus.Connection conn;
    private dynamic DBus.Object networkmanager;
    public void conn_dbus () throws DBus.Error, GLib.Error {
        // remove the space before SYSTEM, it is just needed for this wiki
        this.conn = DBus.Bus.get (DBus.BusType. SYSTEM);

        this.networkmanager = conn.get_object ("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager", "org.freedesktop.NetworkManager");
        this.networkmanager.StateChanged += sig_StateChanged ;
    }
    
    	public uint32 get_state(){
    		return this.networkmanager.State ;
    	}

	// we need a proxy signal to reduce param.
    	private void sig_StateChanged(dynamic DBus.Object obj_,uint32 i){
    		sig_p_StateChanged();
	}
	public signal void sig_p_StateChanged();

}

public delegate int Fuction();
public int connect_to_sig_StateChanged(Fuction fast){
	if (dbus==null){
		return 1;
	}
	dbus.sig_p_StateChanged.connect(() => fast()) ;
	return 0;
}



private RuijieDbus dbus;
private MainLoop loop ;
public int g_loop_run(){
	if(loop==null){
	loop = new MainLoop (null, false);}
	loop.run();
	return 0;
}
public int g_loop_quit(){
	if(loop==null){
		return 1;
	}
	loop.quit();
	return 0;
}
public int dbus_init(){
	if (dbus != null){
		return 1;
	}
	dbus=new RuijieDbus();
        try {
            dbus.conn_dbus ();
        } catch (DBus.Error e) {
            warning ("Failed to initialise");
            return 2;
        } catch (GLib.Error e) {
            warning ("Dynamic method failure");
            return 3;
        }
        return 0;
}
public bool is_networ_ready(){
	if (dbus==null){
		return false;
	}
	if ( (dbus.get_state()) == 3 ) {
	
		return true;
	}
	return false;
}

