/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jboss.pnc.buildagent.server.servlet;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:matejonnet@gmail.com">Matej Lazar</a>
 */
public class Download extends HttpServlet {

    private static Logger log = LoggerFactory.getLogger(Download.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        log.debug("Download servlet requested.");

        String fileLocation = request.getPathInfo();
        File file = new File(fileLocation);
        if (file.isDirectory() || !file.exists()) {
            response.sendError(500);
            log.warn("Invalid file path {}", file);
        }

        response.setContentLength((int) file.length());

        try (ServletOutputStream outputStream = response.getOutputStream()) {
            try (FileInputStream fileInputStream = new FileInputStream(file)) {
                byte[] bytes = new byte[1024];
                int read;
                while ((read = fileInputStream.read(bytes)) != -1) {
                    outputStream.write(bytes, 0, read);
                }
            }
        }
    }

}
