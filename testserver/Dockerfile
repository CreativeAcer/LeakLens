FROM alpine:3.19

RUN apk add --no-cache samba samba-common-tools

# Copy Samba config
COPY smb.conf /etc/samba/smb.conf

# Copy dirty test files into the share
COPY dirty-files/ /shares/testshare/

# Fix permissions
RUN chmod -R 755 /shares/testshare && \
    chown -R nobody:nobody /shares/testshare

EXPOSE 445 139

CMD ["smbd", "--foreground", "--no-process-group", "--log-stdout"]
