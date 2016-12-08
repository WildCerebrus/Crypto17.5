package button;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import ui.Editor;

public class ToSignButton extends FileSelectionButton implements MouseListener{

	public ToSignButton(Editor editor) {
		super(editor);
		this.addMouseListener(this);
		this.setText("SIGNER");
	}

	@Override
	public void mouseClicked(MouseEvent arg0) {
		System.out.println("Signer");
		jfc.showOpenDialog(null);
		
	}

	@Override
	public void mouseEntered(MouseEvent arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void mouseExited(MouseEvent arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void mousePressed(MouseEvent arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void mouseReleased(MouseEvent arg0) {
		// TODO Auto-generated method stub
		
	}

}
