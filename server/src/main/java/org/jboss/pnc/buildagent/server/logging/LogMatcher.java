/**
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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
package org.jboss.pnc.buildagent.server.logging;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jboss.pnc.buildagent.common.StringLiner;

public class LogMatcher {
    private final Pattern pattern;
    private Matcher matcher;
    private boolean matched = false;

    private StringLiner sl = new StringLiner();

    public LogMatcher(Pattern pattern) {
        this.pattern = pattern;
        matcher = pattern.matcher("");
    }

    public void append(String string) {
        sl.append(string);

        String line = sl.nextLine();
        while (line != null) {
            matcher.reset(line);
            if (matcher.find()) {
                matched = true;
            }
            line = sl.nextLine();
        }
    }

    public boolean isMatched() {
        matcher.reset(sl.currentlyBuffered()); // check also last line without newline
        if (matcher.find()) {
            matched = true;
        }
        return matched;
    }
}
