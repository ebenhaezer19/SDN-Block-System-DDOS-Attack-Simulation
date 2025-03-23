FROM osrg/ryu

# Copy DDoS detector application
COPY ddos_detector.py /usr/local/lib/python3.8/dist-packages/ryu/app/

# Set working directory
WORKDIR /usr/local/lib/python3.8/dist-packages/ryu/app/

# Expose Ryu controller port
EXPOSE 6633

# Run Ryu controller with DDoS detector application
CMD ["ryu-manager", "--verbose", "ddos_detector.py"] 