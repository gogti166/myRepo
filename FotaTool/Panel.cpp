#include "Panel.h"
#include <FL/Fl_Input.H>
#include <FL/Fl_Button.H>
#include "fota_tool.h"
#include "common.h"
#include "tcp.h"

int main(int argc, char* argv[])
{
	vInit();
	APP_iWindow();
	return 0;
}

void vButtonTransfer()
{
	//Tool_vFullUpdate();
}

/******************************************
				Connection
*******************************************/
Fl_Button *Btn_GbConnect;
bool boGbConnected = false;
//function called when connected successfully
void vConnected()
{
	printf("connected\n");
	Btn_GbConnect->label("Disconnect");
	boGbConnected = true;
}

void vButtonConnect(Fl_Widget* ThisButton)
{
	if (boGbConnected == false)
	{
		printf("11\n");
		Tcp_tstPcb* stCliPcb = Tcp_vConnect(vConnected);
	}
	else
	{
		printf("dis\n");
		TCP_vClose();
	}
	
}

void vButtonDisconnect()
{

}

/******************************************
				 Window
*******************************************/
int APP_iWindow()
{
	/* "standard" and "plastic" "gtk+" and "gleam"*/
	Fl::scheme("plastic");
	Fl_Window *FlWindow = new Fl_Window(600, 400, "Transfer");
	FlWindow->color(0xE6E6FA00);

	/* Address and Port input box*/
	Fl_Input *IBox_IpAddr = new Fl_Input(100, 40, 150, 30, "Address : ");
	Fl_Input *IBox_Port = new Fl_Input(100 + 150 + 50, 40, 150, 30, "Port : ");
	/* Connected with the input address and port */
	Btn_GbConnect = new Fl_Button(100 + 150 + 50 + 150 + 20, 40, 80, 30, "Connect");
	Btn_GbConnect->callback(vButtonConnect);


	FlWindow->show();
	return Fl::run();
}