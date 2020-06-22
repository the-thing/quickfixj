/*******************************************************************************
 * Copyright (c) quickfixengine.org  All rights reserved.
 *
 * This file is part of the QuickFIX FIX Engine
 *
 * This file may be distributed under the terms of the quickfixengine.org
 * license as defined by quickfixengine.org and appearing in the file
 * LICENSE included in the packaging of this file.
 *
 * This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING
 * THE WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * See http://www.quickfixengine.org/LICENSE for licensing information.
 *
 * Contact ask@quickfixengine.org if any conditions of this licensing
 * are not clear to you.
 ******************************************************************************/

package quickfix;

/**
 * No operation logger implementation.
 */
public final class NoopLog implements Log {

    @Override
    public void clear() {
    }

    @Override
    public void onIncoming(String message) {
    }

    @Override
    public void onOutgoing(String message) {
    }

    @Override
    public void onEvent(String text) {
    }

    @Override
    public void onErrorEvent(String text) {
    }
}
