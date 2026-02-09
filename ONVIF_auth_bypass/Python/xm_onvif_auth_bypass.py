#!/usr/bin/env python3

import sys
import getopt
from onvif import ONVIFCamera

def deps():
    """Collect required user input"""
    ip = ''
    port = 8899
    user = 'admin'
    password = ''
    args = sys.argv[1:]
    options = "i:p:u:s:"
    long_options = ["ip", "port", "user", "secret"]
    try:
        arguments, values = getopt.getopt(args, options, long_options)
        try:
            if '-i' not in args:
                raise Exception("IP address not provided")
        except Exception as e:
            print(f"[+] Usage: python3 script.py -i/--ip <ip> -p/--port [port] -u/--user [user] -s/--secret [password]; Error: {e}")
            sys.exit(1)
        for arg, val in arguments:
            if arg in ("-i", "--ip"):
                ip = val
            elif arg in ("-p", "--port"):
                port = val
            elif arg in ("-u", "--user"):
                user = val
            elif arg in ("-s", "--secret"):
                password = val
    except getopt.GetoptError as err:
        print(str(err))
    print(f"[+] port: {port}")
    print(f"[+] username: {user}")
    print(f"[+] password: {password}")
    return ip, port, user, password

def initialize_camera(ip, port, user, password):
    """Initialize ONVIF connection with IP camera"""
    try:
        cam = ONVIFCamera(ip, port, user, password)
        print(f"[+] Connection established")
    except Exception as e:
        print(f"[-] Failed to connect: {e}")
        sys.exit(1)
    return cam

def get_device_information(cam):
    """Get base device information"""
    try:
        device_management = cam.devicemgmt
        device_info = device_management.GetDeviceInformation()
        print(f"Manufacturer:     {device_info.Manufacturer}")
        print(f"Model:            {device_info.Model}")
        print(f"Firmware:         {device_info.FirmwareVersion}")
        print(f"Serial Number:    {device_info.SerialNumber}")
        print(f"Hardware ID:      {device_info.HardwareId}")
    except Exception as e:
        print(f"[-] Failed to get device info: {e}")

def create_onvif_media_service(cam):
    """Create media service to access and configure RTSP streams"""
    try:
        media = cam.create_media_service()
        print("[+] Media service created successfully")
    except Exception as e:
        print(f"[-] Failed to create media service: {e}")
        sys.exit(1)
    return media

def get_camera_profiles(media):
    """Get available RTSP profiles"""
    try:
        # Get all profiles
        profiles = media.GetProfiles()
        print(f"[+] Found {len(profiles)} profile(s)")

        # Display each profile
        for idx, profile in enumerate(profiles):
            print(f"--- Profile #{idx} ---")
            print(f"Token:            {profile.token}")
            print(f"Name:             {profile.Name}")
            print(f"Fixed:            {profile.fixed}")

            # Video Source Configuration
            if hasattr(profile, 'VideoSourceConfiguration'):
                vsc = profile.VideoSourceConfiguration
                print(f"\n[Video Source]")
                print(f"  Token:          {vsc.token}")
                print(f"  Name:           {vsc.Name}")
                print(f"  Source Token:   {vsc.SourceToken}")
                if hasattr(vsc, 'Bounds'):
                    print(f"  Bounds:         {vsc.Bounds.width}x{vsc.Bounds.height}")

            # Video Encoder Configuration
            if hasattr(profile, 'VideoEncoderConfiguration'):
                vec = profile.VideoEncoderConfiguration
                print(f"\n[Video Encoder]")
                print(f"  Token:          {vec.token}")
                print(f"  Name:           {vec.Name}")
                print(f"  Encoding:       {vec.Encoding}")
                print(f"  Resolution:     {vec.Resolution.Width}x{vec.Resolution.Height}")
                print(f"  Quality:        {vec.Quality}")

                if hasattr(vec, 'RateControl'):
                    rc = vec.RateControl
                    print(f"  Frame Rate:     {rc.FrameRateLimit} FPS")
                    print(f"  Bitrate:        {rc.BitrateLimit} kbps")

                if hasattr(vec, 'H264') and vec.H264:
                    print(f"  H264 Profile:   {vec.H264.H264Profile}")
                    print(f"  GOP Length:     {vec.H264.GovLength}")

            # Audio Encoder Configuration
            if hasattr(profile, 'AudioEncoderConfiguration'):
                aec = profile.AudioEncoderConfiguration
                print(f"\n[Audio Encoder]")
                print(f"  Token:          {aec.token}")
                print(f"  Name:           {aec.Name}")
                print(f"  Encoding:       {aec.Encoding}")
                print(f"  Bitrate:        {aec.Bitrate} kbps")
                print(f"  Sample Rate:    {aec.SampleRate} Hz")

            # PTZ Configuration
            if hasattr(profile, 'PTZConfiguration'):
                ptz = profile.PTZConfiguration
                print(f"\n[PTZ]")
                print(f"  Token:          {ptz.token}")
                print(f"  Name:           {ptz.Name}")
                print(f"  Node Token:     {ptz.NodeToken}")
    except Exception as e:
        print(f"[-] Failed to get profiles: {e}")
    return profiles

def get_rtsp_uri(media, profiles):
    """Get available RTSP URIs from existing profiles"""
    for idx, profile in enumerate(profiles):
        print(f"\n--- Profile #{idx}: {profile.Name} (token: {profile.token}) ---")

        try:
            # Create stream setup request
            stream_setup = {
                'Stream': 'RTP-Unicast',  # RTP-Unicast, RTP-Multicast
                'Transport': {
                    'Protocol': 'RTSP'  # RTSP, UDP, HTTP
                }
            }

            # Get Stream URI
            stream_uri_response = media.GetStreamUri({
                'StreamSetup': stream_setup,
                'ProfileToken': profile.token
            })

            rtsp_uri = stream_uri_response.Uri

            print(f"[+] RTSP URI:")
            print(f"    {rtsp_uri}")

            # Additional metadata
            if hasattr(stream_uri_response, 'InvalidAfterConnect'):
                print(f"    Invalid After Connect: {stream_uri_response.InvalidAfterConnect}")
            if hasattr(stream_uri_response, 'InvalidAfterReboot'):
                print(f"    Invalid After Reboot:  {stream_uri_response.InvalidAfterReboot}")
            if hasattr(stream_uri_response, 'Timeout'):
                print(f"    Timeout:               {stream_uri_response.Timeout}")
        except Exception as e:
            print(f"[-] Failed to get stream URI: {e}")

def main():
    print("="*60)
    print("[*] STEP 0: Connecting to Device")
    print("="*60)

    ip, port, user, password = deps()
    cam = initialize_camera(ip, port, user, password)

    print("="*60)
    print("[*] STEP 1: Getting Device Information")
    print("="*60)

    get_device_information(cam)

    print("="*60)
    print("[*] STEP 2: Creating Media Service")
    print("="*60)

    media = create_onvif_media_service(cam)

    print("="*60)
    print("[*] STEP 3: Getting Media Profiles")
    print("="*60)

    profiles = get_camera_profiles(media)

    print("="*60)
    print("[*] STEP 4: Getting RTSP Stream URIs")
    print("="*60)
    
    get_rtsp_uri(media, profiles)

if __name__ == "__main__":
    main()
