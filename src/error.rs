error_chain! {
    errors {
        BuildPacketError
        ParsePacketError
        SendPacketError
        CreateChannelError
    }

    foreign_links {
        IOError(::std::io::Error);
        SysTimeError(::std::time::SystemTimeError);
    }
}
